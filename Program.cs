using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace DMPWalker
{
    class Program
    {
        private static readonly byte[] PE_SIGNATURE = { 0x4D, 0x5A }; // "MZ"
        private static readonly byte[] PE_HEADER = { 0x50, 0x45, 0x00, 0x00 }; // "PE\0\0"

        static void Main(string[] args)
        {

            if (args.Length == 0)
            {
                Console.WriteLine("DMPWalker.exe <.dmp file> [Output Path]");
                return;
            }

            string dumpFilePath = args[0];
            string outputDir = args.Length > 1 ? args[1] : Path.Combine(Path.GetDirectoryName(dumpFilePath), "extracted");

            if (!File.Exists(dumpFilePath))
            {
                Console.WriteLine($"File doee not exist - {dumpFilePath}");
                return;
            }

            try
            {
                ExtractBinariesFromDump(dumpFilePath, outputDir);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }

            Console.ReadKey();
        }

        static void ExtractBinariesFromDump(string dumpFilePath, string outputDir)
        {
            Console.WriteLine($"Walking: {dumpFilePath}");
            Console.WriteLine($"Output: {outputDir}");

            if (!Directory.Exists(outputDir))
            {
                Directory.CreateDirectory(outputDir);
            }

            byte[] dumpData = File.ReadAllBytes(dumpFilePath);
            Console.WriteLine($"File size: {dumpData.Length:N0} bytes.");

            List<PEFile> peFiles = FindPEFiles(dumpData);
            Console.WriteLine($"Found {peFiles.Count} PE Files");

            int extractedCount = 0;
            foreach (var peFile in peFiles)
            {
                try
                {
                    ExtractPEFile(dumpData, peFile, outputDir, extractedCount);
                    extractedCount++;
                    Console.WriteLine($"Extracted {peFile.FileName} (Offset: 0x{peFile.Offset:X8}, Size: {peFile.Size:N0} bytes)");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Failed to extract {peFile.FileName}: {ex.Message}");
                }
            }

            Console.WriteLine($"\nDone! Extracted {extractedCount} files.");
        }

        static List<PEFile> FindPEFiles(byte[] data)
        {
            List<PEFile> peFiles = new List<PEFile>();

            for (int i = 0; i < data.Length - 64; i++)
            {
                if (data[i] == PE_SIGNATURE[0] && data[i + 1] == PE_SIGNATURE[1])
                {
                    try
                    {
                        var peFile = AnalyzePEFile(data, i);
                        if (peFile != null)
                        {
                            peFiles.Add(peFile);
                            i += Math.Max(1024, peFile.Size / 100);
                        }
                    }
                    catch
                    {
                    }
                }
            }

            return peFiles;
        }

        static PEFile AnalyzePEFile(byte[] data, int offset)
        {
            if (offset + 64 >= data.Length) return null;

            uint peOffset = BitConverter.ToUInt32(data, offset + 60);
            if (peOffset == 0 || offset + peOffset + 24 >= data.Length) return null;

            int peSignaturePos = (int)(offset + peOffset);
            if (peSignaturePos + 4 >= data.Length) return null;

            if (!data.Skip(peSignaturePos).Take(4).SequenceEqual(PE_HEADER))
                return null;

            int coffHeaderPos = peSignaturePos + 4;
            if (coffHeaderPos + 20 >= data.Length) return null;

            ushort machine = BitConverter.ToUInt16(data, coffHeaderPos);
            ushort numberOfSections = BitConverter.ToUInt16(data, coffHeaderPos + 2);
            ushort sizeOfOptionalHeader = BitConverter.ToUInt16(data, coffHeaderPos + 16);

            if (numberOfSections == 0 || numberOfSections > 100) return null;

            int optionalHeaderPos = coffHeaderPos + 20;
            if (optionalHeaderPos + sizeOfOptionalHeader >= data.Length) return null;

            ushort magic = BitConverter.ToUInt16(data, optionalHeaderPos);
            bool is64bit = magic == 0x20b;

            int sectionHeaderPos = optionalHeaderPos + sizeOfOptionalHeader;
            int maxSize = 0;

            for (int i = 0; i < numberOfSections; i++)
            {
                int sectionPos = sectionHeaderPos + (i * 40);
                if (sectionPos + 40 >= data.Length) break;

                uint rawSize = BitConverter.ToUInt32(data, sectionPos + 16);
                uint rawPointer = BitConverter.ToUInt32(data, sectionPos + 20);

                if (rawPointer + rawSize > maxSize)
                    maxSize = (int)(rawPointer + rawSize);
            }

            if (maxSize == 0 || maxSize > data.Length - offset)
                maxSize = Math.Min(0x100000, data.Length - offset); //1MB

            string fileName = ExtractFileName(data, offset, is64bit) ?? $"unknown_{offset:X8}";
            string extension = DetermineFileExtension(data, coffHeaderPos);
            if (!fileName.Contains('.'))
                fileName += extension;

            return new PEFile
            {
                Offset = offset,
                Size = maxSize,
                FileName = fileName,
                Is64Bit = is64bit,
                Machine = machine,
                NumberOfSections = numberOfSections
            };
        }

        static string ExtractFileName(byte[] data, int peOffset, bool is64bit)
        {
            try
            {
                uint peHeaderOffset = BitConverter.ToUInt32(data, peOffset + 60);
                int optionalHeaderOffset = (int)(peOffset + peHeaderOffset + 24);
                int exportTableRvaOffset = optionalHeaderOffset + (is64bit ? 112 : 96);
                if (exportTableRvaOffset + 4 >= data.Length) return null;

                uint exportTableRva = BitConverter.ToUInt32(data, exportTableRvaOffset);
                if (exportTableRva == 0) return null;
                int nameRvaOffset = RvaToFileOffset(data, peOffset, exportTableRva + 12);
                if (nameRvaOffset == -1) return null;

                uint nameRva = BitConverter.ToUInt32(data, nameRvaOffset);
                int nameOffset = RvaToFileOffset(data, peOffset, nameRva);

                if (nameOffset != -1)
                {
                    return ReadNullTerminatedString(data, nameOffset);
                }
            }
            catch { }

            return null;
        }

        static int RvaToFileOffset(byte[] data, int peOffset, uint rva)
        {
            try
            {
                uint peHeaderOffset = BitConverter.ToUInt32(data, peOffset + 60);
                int coffHeaderPos = (int)(peOffset + peHeaderOffset + 4);
                ushort numberOfSections = BitConverter.ToUInt16(data, coffHeaderPos + 2);
                ushort sizeOfOptionalHeader = BitConverter.ToUInt16(data, coffHeaderPos + 16);

                int sectionHeaderPos = coffHeaderPos + 20 + sizeOfOptionalHeader;

                for (int i = 0; i < numberOfSections; i++)
                {
                    int sectionPos = sectionHeaderPos + (i * 40);
                    if (sectionPos + 40 >= data.Length) break;

                    uint virtualAddress = BitConverter.ToUInt32(data, sectionPos + 12);
                    uint virtualSize = BitConverter.ToUInt32(data, sectionPos + 8);
                    uint rawPointer = BitConverter.ToUInt32(data, sectionPos + 20);

                    if (rva >= virtualAddress && rva < virtualAddress + virtualSize)
                    {
                        return (int)(peOffset + rawPointer + (rva - virtualAddress));
                    }
                }
            }
            catch { }

            return -1;
        }

        static string ReadNullTerminatedString(byte[] data, int offset)
        {
            if (offset >= data.Length) return null;

            int length = 0;
            while (offset + length < data.Length && data[offset + length] != 0)
                length++;

            if (length == 0) return null;
            return Encoding.ASCII.GetString(data, offset, length);
        }

        static string DetermineFileExtension(byte[] data, int coffHeaderPos)
        {
            ushort characteristics = BitConverter.ToUInt16(data, coffHeaderPos + 18);
            if ((characteristics & 0x2000) != 0)
                return ".dll";
            else if ((characteristics & 0x0002) != 0)
                return ".exe";
            else
                return ".bin";
        }

        static void ExtractPEFile(byte[] dumpData, PEFile peFile, string outputDir, int index)
        {
            byte[] fileData = new byte[peFile.Size];
            Array.Copy(dumpData, peFile.Offset, fileData, 0, peFile.Size);

            string fileName = SanitizeFileName(peFile.FileName);
            if (string.IsNullOrEmpty(fileName))
                fileName = $"extracted_{index:D3}_{peFile.Offset:X8}.bin";

            string filePath = Path.Combine(outputDir, fileName);

            int counter = 1;
            string originalPath = filePath;
            while (File.Exists(filePath))
            {
                string nameWithoutExt = Path.GetFileNameWithoutExtension(originalPath);
                string ext = Path.GetExtension(originalPath);
                filePath = Path.Combine(outputDir, $"{nameWithoutExt}_{counter}{ext}");
                counter++;
            }

            File.WriteAllBytes(filePath, fileData);
        }

        static string SanitizeFileName(string fileName)
        {
            if (string.IsNullOrEmpty(fileName)) return null;

            char[] invalidChars = Path.GetInvalidFileNameChars();
            StringBuilder sb = new StringBuilder();

            foreach (char c in fileName)
            {
                if (!invalidChars.Contains(c))
                    sb.Append(c);
                else
                    sb.Append('_');
            }

            return sb.ToString();
        }
    }

    class PEFile
    {
        public int Offset { get; set; }
        public int Size { get; set; }
        public string FileName { get; set; }
        public bool Is64Bit { get; set; }
        public ushort Machine { get; set; }
        public ushort NumberOfSections { get; set; }
    }
}
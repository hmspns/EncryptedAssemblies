using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using System.Threading.Tasks;
using EncryptedAssemblies.Starter;
using EncryptedAssemblies.Starter.Cryptography;
using EncryptedAssemblies.TestApplication;

namespace EncryptedAssemblies
{
    class Program
    {
        [DllImport("user32.dll")]
        public static extern IntPtr FindWindow(string lpClassName, string lpWindowName);

        [DllImport("user32.dll")]
        static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

        static Program()
        {
            AppDomain.CurrentDomain.UnhandledException += (sender, eventArgs) => Console.WriteLine(eventArgs.ExceptionObject.ToString());
            AppDomain.CurrentDomain.AssemblyResolve += CurrentDomainOnAssemblyResolve;
            _password = new SecureString();
        }

        private static readonly SecureString _password;

        [STAThread]
        public static void Main(string[] args)
        {
            //Выводит фейковое сообщение об ошибке
            try
            {
                ArgumentException ex = new ArgumentException("There is not enough data to start application");
                throw ex;
            }
            catch (ArgumentException ex)
            {
                Console.WriteLine(ex.ToString());
                Console.WriteLine("Press Esc to exit");
            }

            if (!ReadPassword())
                return;

            if (args.Length == 0)
                RunApplication();
            else
            {
                switch (args[0].TrimStart('-', '/', '\\').ToLower())
                {
                    case "help":
                    case "h":
                    case "?":
                        Console.WriteLine("Encrypt assemblies: -ea");
                        break;

                    case "ea": //зашифровать сборки
                        EncryptAssemblies();
                        break;
                }
            }

        }

        private static bool ReadPassword()
        {
            ConsoleKeyInfo consoleKey = Console.ReadKey(true);

            while (consoleKey.Key != ConsoleKey.Enter)
            {
                if (consoleKey.Key == ConsoleKey.Escape)
                {
                    return false;
                }
                _password.AppendChar(consoleKey.KeyChar);
                consoleKey = Console.ReadKey(true);
            }
            return _password.Length > 0;
        }

        private static void RunApplication()
        {
            SetConsoleWindowVisibility(false);

            App app = new App();
            MainWindow window = new MainWindow();
            app.Run(window);
        }

        /// <summary>
        /// Зашифровывает сборки и удаляет оригинальные файлы.
        /// </summary>
        private static void EncryptAssemblies()
        {
            Wiper wiper = new Wiper();
            foreach (string file in Directory.GetFiles(AppDomain.CurrentDomain.BaseDirectory, "*.dll"))
            {
                byte[] source = File.ReadAllBytes(file);
                CryptedData crypted = CryptographyHelper.Encrypt(source, _password);
                string resultPath = Path.Combine(Path.GetDirectoryName(file), Path.GetFileNameWithoutExtension(file) + ".edll");
                File.WriteAllBytes(resultPath, crypted.ToArray());
                //удаляем оригинальную сборку
                wiper.WipeFile(file, 3);
                //File.Delete(file);
            }
            string currentAssemblyName = Assembly.GetEntryAssembly().GetName().Name;
            foreach (string file in Directory.GetFiles(AppDomain.CurrentDomain.BaseDirectory, "*.pdb"))
            {
                if (Path.GetFileNameWithoutExtension(file) == currentAssemblyName)
                    continue;
                byte[] source = File.ReadAllBytes(file);
                CryptedData crypted = CryptographyHelper.Encrypt(source, _password);
                string resultPath = Path.Combine(Path.GetDirectoryName(file), Path.GetFileNameWithoutExtension(file) + ".epdb");
                File.WriteAllBytes(resultPath, crypted.ToArray());
                //удаляем оригинальную сборку
                wiper.WipeFile(file, 3);
            }
        }

        /// <summary>
        /// Обработчик подгрузки сборки.
        /// </summary>
        private static Assembly CurrentDomainOnAssemblyResolve(object sender, ResolveEventArgs args)
        {
            string[] fileParts = args.Name.Split(",".ToCharArray());

            string assemblyPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, fileParts[0] + ".edll");
            string symbolsPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, fileParts[0] + ".epdb");
            byte[] assemblyBytes = null, symbolsBytes = null;
            if (File.Exists(assemblyPath))
            {
                assemblyBytes = DecryptFile(assemblyPath);
            }
            if (File.Exists(symbolsPath))
            {
                symbolsBytes = DecryptFile(symbolsPath);
            }
            return Assembly.Load(assemblyBytes, symbolsBytes);
        }

        /// <summary>
        /// Расшифровывает файл.
        /// </summary>
        /// <param name="path">Путь к файлы.</param>
        /// <returns>Расшифрованные данные файла.</returns>
        private static byte[] DecryptFile(string path)
        {
            CryptedData data;
            using (FileStream fs = File.OpenRead(path))
            {
                data = CryptedData.Create(fs);
            }
            byte[] bytes = CryptographyHelper.Decrypt(data, _password);
            return bytes;
        }

        /// <summary>
        /// Устанавливает видимость окна консоли.
        /// </summary>
        /// <param name="visible">Видимость окна консоли.</param>
        private static void SetConsoleWindowVisibility(bool visible)
        {          
            IntPtr hWnd = FindWindow(null, Console.Title);

            if (hWnd != IntPtr.Zero)
            {
                if (visible)
                    ShowWindow(hWnd, 1); //1 = SW_SHOWNORMAL           
                else
                    ShowWindow(hWnd, 0); //0 = SW_HIDE               
            }
        }
    }
}

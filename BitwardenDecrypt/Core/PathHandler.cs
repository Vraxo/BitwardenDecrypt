namespace BitwardenDecryptor.Core;

public static class PathHandler
{
    public static void HandleInstallPath()
    {
        try
        {
            string exeDir = GetExecutableDirectory();
            Console.WriteLine($"Attempting to add '{exeDir}' to the user PATH variable.");

            string pathVar = Environment.GetEnvironmentVariable("PATH", EnvironmentVariableTarget.User) ?? "";
            List<string> paths = pathVar.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries).ToList();

            if (paths.Any(p => p.Equals(exeDir, StringComparison.OrdinalIgnoreCase)))
            {
                Console.WriteLine("Application directory is already in the user PATH. No changes made.");
                return;
            }

            paths.Add(exeDir);
            string newPath = string.Join(Path.PathSeparator, paths);
            Environment.SetEnvironmentVariable("PATH", newPath, EnvironmentVariableTarget.User);

            Console.WriteLine("\nSuccessfully added application directory to the user PATH.");
            Console.WriteLine("You may need to restart your terminal/shell or log out and back in for the changes to take effect.");
        }
        catch (Exception ex)
        {
            ConsoleExceptionHandler.Handle(ex);
            Environment.ExitCode = 1;
        }
    }

    public static void HandleUninstallPath()
    {
        try
        {
            string exeDir = GetExecutableDirectory();
            Console.WriteLine($"Attempting to remove '{exeDir}' from the user PATH variable.");

            string? pathVar = Environment.GetEnvironmentVariable("PATH", EnvironmentVariableTarget.User);
            if (string.IsNullOrEmpty(pathVar))
            {
                Console.WriteLine("User PATH is empty or not set. No changes needed.");
                return;
            }

            List<string> paths = pathVar.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries).ToList();
            int removedCount = paths.RemoveAll(p => p.Equals(exeDir, StringComparison.OrdinalIgnoreCase));

            if (removedCount > 0)
            {
                string newPath = string.Join(Path.PathSeparator, paths);
                Environment.SetEnvironmentVariable("PATH", newPath, EnvironmentVariableTarget.User);
                Console.WriteLine("\nSuccessfully removed application directory from the user PATH.");
                Console.WriteLine("You may need to restart your terminal/shell or log out and back in for the changes to take effect.");
            }
            else
            {
                Console.WriteLine("Application directory was not found in the user PATH. No changes made.");
            }
        }
        catch (Exception ex)
        {
            ConsoleExceptionHandler.Handle(ex);
            Environment.ExitCode = 1;
        }
    }

    private static string GetExecutableDirectory()
    {
        string? exePath = Environment.ProcessPath;
        if (string.IsNullOrEmpty(exePath))
        {
            throw new InvalidOperationException("Could not determine the application's path.");
        }

        string? exeDir = Path.GetDirectoryName(exePath);
        if (string.IsNullOrEmpty(exeDir))
        {
            throw new InvalidOperationException("Could not determine the application's directory.");
        }

        return exeDir;
    }
}
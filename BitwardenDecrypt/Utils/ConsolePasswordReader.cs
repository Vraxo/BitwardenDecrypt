using System.Text;

namespace BitwardenDecryptor.Utils;

public static class ConsolePasswordReader
{
    public static string ReadPassword(string prompt)
    {
        Console.Write(prompt);

        StringBuilder password = new();

        while (true)
        {
            ConsoleKeyInfo keyInfo = Console.ReadKey(true);

            if (keyInfo.Key == ConsoleKey.Enter)
            {
                Console.WriteLine();
                break;
            }

            if (keyInfo.Key == ConsoleKey.Backspace && password.Length > 0)
            {
                _ = password.Remove(password.Length - 1, 1);
            }
            else if (!char.IsControl(keyInfo.KeyChar))
            {
                _ = password.Append(keyInfo.KeyChar);
            }
        }

        return password.ToString();
    }
}
namespace BitwardenDecryptor;

public class CommandLineOptions
{
    public string InputFile { get; set; } = "data.json";
    public bool IncludeSends { get; set; } = false;
    public string? OutputFile { get; set; }
}
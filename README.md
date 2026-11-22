# Driver Scanner

Driver Scanner uses static analysis to look for potential security issues in Windows kernel drivers. Point it at a folder of `.sys` files to review IOCTL paths, memory operations, signatures, and installed Microsoft deny-hash matches.

## What it checks

- Recovers supported x64 WDM device-control handlers and traces request-derived values through their code paths.
- Flags potential memory read, write, and mapping issues, with separate results for paths that need more context.
- Records recovered IOCTL values, handler and operation RVAs, access sizes, and branch conditions.
- Checks embedded signatures and locally installed catalog signatures, with certificate status beside the company name.
- Compares Authenticode SHA-256 hashes against the installed Microsoft driver deny rules.
- Shows analysis gaps alongside the findings. Results can be filtered, searched, and exported as CSV or JSON.

## Build

Use Visual Studio 2022 with **Desktop development with C++** and a Windows SDK installed.

```powershell
msbuild .\drvscanner.sln /p:Configuration=Release /p:Platform=x64
```

The executable is written to `x64\Release\Driver Scanner.exe`. Instruction tracing also needs the Visual Studio C++ tools (`dumpbin.exe`) installed on the machine running the scanner.

## Use

Launch the executable, choose a folder, and click **Start analysis**. The scan includes subfolders. Select a driver to inspect its findings, code locations, and coverage notes. **Export CSV** saves the current scan results.

For a JSON report, run:

```powershell
& ".\x64\Release\Driver Scanner.exe" --scan "C:\Drivers" --output ".\scan.json"
```

The output file must be new; existing reports are preserved. `--help` lists the command-line options and exit codes. Exit code `1` means the report has incomplete coverage or an analysis error, so check the report before treating it as a failed scan.

## Reading the results

| Result | Meaning |
| --- | --- |
| Policy match | The image's Authenticode hash matches a loaded deny rule. |
| Request flow | Request-derived data reaches a modeled memory operation. |
| Qualified flow | A traced operation needs more context because of guards, unresolved calls, or other limitations. |
| Pattern lead | An instruction pattern was found without a recovered request-to-operation path. |
| Metadata only | File information or API indicators were collected without stronger evidence. |
| Analysis error | The file could not be analyzed successfully. |

These results are starting points for manual review, not confirmed vulnerabilities. Check whether callers can reach the handler, what access the device allows, and whether validation exists outside the recovered path.

The tracing engine supports a bounded subset of x64 WDM code and has a 10-second reversing budget per image. KMDF callbacks, unresolved indirect calls, exceptions, and unsupported instructions can leave gaps. Check **Coverage** even when no findings are listed. The scanner does not load drivers or test exploitability.

Certificate checks run offline. `Valid` does not establish current revocation status, and timestamped signatures can remain trusted after the signing certificate expires. The **Overview** tab includes the detailed verification result. Company and version fields come from file metadata.

The policy lookup covers installed Authenticode SHA-256 deny rules. It does not evaluate signer, version, or page-hash rules. A missing match is not a clean bill of health.

## License

MIT. See [LICENSE](LICENSE) for the original copyright and license terms.

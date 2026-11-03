# PromptSafe

PromptSafe hides passwords, keys, IPs, names and other sensitive data in your
logs and text **before you paste them into an AI**. Each value becomes a
placeholder like `IP_1` or `PASSWORD_1`, and you can put the real values back
into the AI's answer afterwards. Runs 100% offline on Linux and Windows.

```
before: Accepted password for johndoe from 192.168.10.45 port 52144
after:  Accepted password for USER_1 from IP_1 port 52144
```

## Install

**Linux**

```sh
curl -fsSL https://github.com/ayourr/PromptSafe/releases/latest/download/install.sh | sh
```

**Windows** (PowerShell)

```powershell
irm https://github.com/ayourr/PromptSafe/releases/latest/download/install.ps1 | iex
```

Or download the file for your system from the
[Releases page](https://github.com/ayourr/PromptSafe/releases/latest).

## Use

```sh
promptsafe redact app.log > safe.txt     # clean a file, then paste safe.txt into the AI
promptsafe gui                           # same thing in a window (opens in your browser)
```

Add your own sensitive words (company, project, people), one per line:

```sh
promptsafe redact -w words.txt app.log > safe.txt
```

Get the real values back in the AI's answer:

```sh
promptsafe redact -m map.json app.log > safe.txt
promptsafe restore -m map.json answer.txt
```

If anything sensitive is still left, PromptSafe blocks the output instead of
printing it.

## More

All commands, options, detectors, the config file and known limits are in
[docs/reference.md](docs/reference.md).

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

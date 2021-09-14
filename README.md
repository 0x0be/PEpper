<p align="center">
    <img src="https://raw.githubusercontent.com/Th3Hurrican3/PEpper/media/logo.jpg" alt="mitmlogo">
</p>

<h3 align="center">PEpper</h3>
<p align="center">
    An open source tool to perform <i>malware static analysis</i> on <b>P</b>ortable <b>E</b>xecutable
</p>

# Installation

```console
eva@paradise:~$ git clone https://github.com/blackeko/PEpper/
eva@paradise:~$ cd PEpper
eva@paradise:~$ pip3 install -r requirements.txt
eva@paradise:~$ python3 pepper.py ./malware_dir
```

# Screenshot

<table style="width:100%">
		<tr>
			<td><img src="https://raw.githubusercontent.com/blackeko/PEpper/media/1.png" ></td>
			<td><img src="https://raw.githubusercontent.com/blackeko/PEpper/media/2.png" ></td>
		</tr>
		<tr>
			<td><img src="https://raw.githubusercontent.com/blackeko/PEpper/media/3.png" ></td>
			<td><img src="https://raw.githubusercontent.com/blackeko/PEpper/media/4.png" ></td>
		</tr>
</table>

and more rows..

# CSV output

<p>
  <img src="https://raw.githubusercontent.com/blackeko/PEpper/media/csv.png" alt="outcome">
</p>

and more columns..

# Feature extracted

- **Suspicious entropy** ratio
- **Suspicious name** ratio
- Suspicious **code size**
- Suspicious **debugging time-stamp** 
- Number of **export**
- Number of **anti-debugging** calls
- Number of **virtual-machine detection** calls
- Number of **suspicious API** calls
- Number of **suspicious strings**
- Number of **YARA** rules matches 
- Number of **URL** found
- Number of **IP** found
- *Cookie on the stack* (**GS**) support
- *Control Flow Guard* (**CFG**) support
- *Data Execution Prevention* (**DEP**) support
- *Address Space Layout Randomization* (**ASLR**) support
- *Structured Exception Handling* (**SEH**) support
- *Thread Local Storage* (**TLS**) support
- Presence of **manifest**
- Presence of **version**
- Presence of **digital certificate**
- **Packer** detection
- **VirusTotal** database detection
- **Import hash**

# Notes

- Can be run on *single* or *multiple* PE (placed inside a directory)
- Output will be saved (in the same directory of *pepper.py*) as **FILENAME-output.csv**
- To use **VirusTotal scan**, add your private key in the module called "virustotal.py" (Internet connection required)
- <img alt="Software License" src="https://img.shields.io/badge/license-GPL3-brightgreen.svg?style=flat-square">

# Credits

Many thanks to those who indirectly helped me in this work, specially:

- The [LIEF](https://github.com/lief-project/LIEF) project and its awesome library
- [PEstudio](https://www.winitor.com/), a really amazing software to analyze PE
- [PEframe](https://github.com/guelfoweb/peframe) from [guelfoweb](https://github.com/guelfoweb), an incredible widespread tool to perform static analysis on Portable Executable malware and malicious MS Office documents
- [Yara-Rules](https://github.com/Yara-Rules/rules) project, which provides compiled signatures, classified and kept as up to date as possible

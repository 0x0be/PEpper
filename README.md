<p align="center">
    <img src="https://raw.githubusercontent.com/Th3Hurrican3/PEpper/media/logo.jpg" alt="mitmlogo">
</p>

<h3 align="center">PEpper</h3>
<p align="center">
    An open source tool to perform <i>malware static analysis</i> on <b>P</b>ortable <b>E</b>xecutable
</p>

# Installation

```console
eva@paradise:~$ git clone https://github.com/Th3Hurrican3/PEpper/
eva@paradise:~$ cd PEpper
eva@paradise:~$ pip3 install -r requirements.txt
eva@paradise:~$ python3 pepper.py ./malware_dir
```

# Screenshot

 <div class="row">
  <div class="column">
    <img src="https://raw.githubusercontent.com/Th3Hurrican3/PEpper/media/1.png" alt="Screenshot" style="width:100%">
  </div>
  <div class="column">
    <img src="https://raw.githubusercontent.com/Th3Hurrican3/PEpper/media/2.png" alt="Screenshot" style="width:100%">
</div> 

and more rows..

# CSV output

<p>
  <img src="https://raw.githubusercontent.com/Th3Hurrican3/PEpper/media/csv.png" alt="outcome">
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
- Output will be saved (in the same directory of *pepper.py*) as **output.csv**
- To use **VirusTotal scan**, add your private key in the module called "virustotal.py" (Internet connection required)
- Of course, that will increase the scan time
- <img alt="Software License" src="https://img.shields.io/badge/license-GPL3-brightgreen.svg?style=flat-square">

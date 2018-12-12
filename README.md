# Byeongal Static Report
Byeongal Static Report is an automated static analysis open source software. You can get a report( md5.json ) which contains following informatioin:
* File Hash ( md5, sha1, and sha256 )
* PE File Information ( Section, Compile Information, Resources, Import, Export, API and imphash )

## Usage
```bash
$ python byeongal_static.py <file_path> 
```

## Update Log
### Update 2018.12
* File Hash Information ( md5, sha1, sha256 )
* File Magic
* PE File Information
  * imphash
  * Compile Time
  * Packer Information
  * Sections Information
  * Resources Information
  * Import and Export
  * API Alert
* Yara
  * Anti Debugging
  
## Reference
To create this software, I refer to the following software:
* [PEframe 5.0.1](https://github.com/guelfoweb/peframe)

## Contact
If you want to contact me, please send me an email to my email address(corea_kyj@naver.com).
* Ps. I can understand only English and Korean and prefer to use Korean.

## License
[![License](https://img.shields.io/:license-gpl3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0.html)
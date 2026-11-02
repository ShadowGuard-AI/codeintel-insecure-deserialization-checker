![A veranda under low cloud with no text anywhere: the name board blank, the diary shut, the barometer face turned away, a rain gauge on the rail, a weather vane on the ridge, an empty garden path, and one band of dawn apricot light at the edge of the cloud](intro-banner.png)



# codeintel-Insecure-Deserialization-Checker

![The veranda at the moment before the rain arrives: heavy still sky, dark green wet looking garden, the barometer needle pointing low, the vane pointing toward the coming weather, an empty rain gauge on the rail, the diary open with a pencil beside it, and the project name painted on the name board above the steps](banner.png)

![One veranda with a tiled roof on plain posts, a rail across the front, a chair and a small table behind the rail with an open blank diary on it, and a barometer with a silver rim on the post beside the chair, over the project name lettered like a forecast entry, the heading plate](logo.png)

![The veranda in three bands: cloud thickening slowly and then thinning in the far band, the veranda standing still in the middle band while its vane turns in small steps and its barometer needle falls slowly and rises after, and rain drops falling through the near band during the wet part of the cycle while the diary stays dry under the roof](scene.svg)

Detects potential insecure deserialization vulnerabilities by analyzing code for usage of pickle or similar libraries without proper input validation. Focuses on identifying deserialization calls on untrusted data. - Focused on Tools for static code analysis, vulnerability scanning, and code quality assurance

![Major separator: a full row of rain drops falling through the rule and splashing](sep-heavy.svg)

## Install
`git clone https://github.com/ShadowStrikeHQ/codeintel-insecure-deserialization-checker`

> **Diary margin note, wrong name on the address.** The clone line above names ShadowStrikeHQ rather than ShadowGuard-AI. It is kept as printed and flagged here, not corrected in the display. The repository LICENSE file carries the MIT License, while the closing line of this README reads Copyright (c) ShadowStrikeHQ; both facts stand as printed.


![Major separator: a full row of rain drops falling through the rule and splashing](sep-heavy.svg)

## Usage
`./codeintel-insecure-deserialization-checker [params]`

> **Diary margin note, the path argument is missing.** The usage line above is a placeholder that the parser does not accept. The line the parser accepts is `python3 main.py FILEPATH [-v] [-e PATH ...] [-o FILE]`, where filepath is a required argument naming one Python file or one directory, and it appears in no parameter entry below. Its restoration lives on the website only, marked there, so the gap remains visible where it was found.


![Major separator: a full row of rain drops falling through the rule and splashing](sep-heavy.svg)

## Parameters
- `-h`: Show help message and exit
- `-v`: No description provided
- `-e`: List of files or directories to exclude from analysis.
- `-o`: Path to output file for scan results.  If omitted, results will be printed to the console.

![Minor separator: a short centred row of rain drops falling through the rule and splashing](sep-light.svg)

> **Diary margin note, exclusion works by plain prefix.** The code tests exclusions as simple text prefixes, not checked against a path boundary, so excluding a path called data also excludes a neighbouring path called database. This caution is recorded here because the README entry above does not mention it.


![Major separator: a full row of rain drops falling through the rule and splashing](sep-heavy.svg)

## License
Copyright (c) ShadowStrikeHQ

> **Diary margin note, wrong name on the address.** The copyright line above names ShadowStrikeHQ rather than ShadowGuard-AI. It is kept as printed and flagged here. The repository LICENSE file carries the MIT License.

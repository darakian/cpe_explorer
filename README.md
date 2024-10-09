# cpe_explorer

An opinionated command line tool used to explore the nvd CPE dictionary.
The dictionary itself is [available here](https://nvd.nist.gov/products/cpe) and seems to update daily.

```
Usage: cpe_explorer [OPTIONS] --dict <DICT>

Options:
  -d, --dict <DICT>                Path to cpe dictionary xml
  -j, --json-out <JSON_OUT>        [possible values: true, false]
  -c, --compress-versions
  -v, --vendor <VENDOR>
  -p, --product <PRODUCT>
  -p, --valid-cpe23 <VALID_CPE23>  [possible values: true, false]
  -h, --help                       Print help
  -V, --version                    Print version
  ```

Currently under active development, but it's currently most useful in getting cpe23 strings that match a given vendor and/or product.
eg.
```
darakian~/g/p/cpe_explorer:main❯❯❯ cpe_explorer -d official-cpe-dictionary_v2.3-03102024.xml -v nist
Matching cpe: "cpe:2.3:a:nist:hipaa_security_rule_toolkit:1.0.0.0:*:*:*:*:*:*:*"
```
```
darakian~/g/p/cpe_explorer:main❯❯❯ cpe_explorer -d official-cpe-dictionary_v2.3-03102024.xml -p cve-services
Matching cpe: "cpe:2.3:a:cve:cve-services:-:*:*:*:*:*:*:*"
Matching cpe: "cpe:2.3:a:cve:cve-services:1.0.0:*:*:*:*:*:*:*"
Matching cpe: "cpe:2.3:a:cve:cve-services:1.0.1:*:*:*:*:*:*:*"
Matching cpe: "cpe:2.3:a:cve:cve-services:1.1.1:*:*:*:*:*:*:*"
```
```
darakian~/g/p/cpe_explorer:main❯❯❯ cpe_explorer -d official-cpe-dictionary_v2.3-03102024.xml -v palm -p blazer
Matching cpe: "cpe:2.3:a:palm:blazer:3.0:*:*:*:*:*:*:*"
Matching cpe: "cpe:2.3:a:palm:blazer:4.0:*:*:*:*:*:*:*"
Matching cpe: "cpe:2.3:a:palm:blazer:4.2:*:*:*:*:*:*:*"
Matching cpe: "cpe:2.3:a:palm:blazer:4.3:*:*:*:*:*:*:*"
Matching cpe: "cpe:2.3:a:palm:blazer:4.5:*:*:*:*:*:*:*"
```
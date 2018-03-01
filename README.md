# SignatureMiner: A AV Intelligence tool

SignatureMiner is a python tool to mine information from cryptic Antivirus software signatures. It was designed to extract consensus about malware types from the outputs of Multi-scanner tools, but can be leveraged to extract (or mine) useful insights from the signatures themselves.

SignatureMiner leverages the well-known minhashing approach to cluster together tokens extracted from clean AV signatures. Those clusters have to be supervised by the user to write some regular expression rules (in python) that SignatureMiner can convert into classification directives. To do this, SignatureMiner has two components: A Miner component and an Assigner component

## Miner component

The miner component (classMiner.py) takes as input a JSON style file containing a field "av_labels" which has, for each detection a tuple containing the AV engine and the signature. For instance:

```{"av_labels": [["AV4", "ADWARE/ANDR.Airpush.G.Gen"], ["AV6", "ANDROIDOS_ARPUSH.HRXV"]}```

The usage is as follows:

```python classMiner.py <labelFile> <outputFile> [MinhashKey] [ruleFile] [Tokenize (yes|no)]```

Where *labelFile* is the aforementioned input file, *outputFile* is the name for the output file, *MinhashKey* is the length of the minhashing shingles, *ruleFile* is the optional file of the rules that have been already developed and *Tokenize* specifies whether tokenization by dots is expected.

This program outputs its results to another JSON file, which combines the minhash of tokens and the counts of different tokens that have been grouped together.

The Minhash key is the length of the generated shingles to compute minhashing. A Shingle is just a subset of each signature to be hashed of preset length. By default, this length is 5. 


## Assigner Component

This program receives as input the same file as the Miner component and a rule file which specifies the directives to determine the class of a signature. It outputs either a collection of classes when mode is MULTI and one single class (through majority voting) when SINGLE mode is selected. The usage is as follows:

```python classAssigner.py <labelFile> <outputFile> <ruleFile> <Mode>```

*ruleFile* now is required, as it is the set of rules used for classification. *Mode* represents the operation mode to be used and currently supports either SINGLE, for classification and majority class voting and MULTI for simple classification of different AV engines at once for the same sample.

## Rules File

Rules file is a set of directives that tell SignatureMiner how to proceed upon signatures. Its syntax is the following:

```RegExp -> RegExpName```

For instance: 

```.*a[ir]*push?.*->airpush```
```.*revmob.*->revmob```

The rules are interpreted and applied in order of appearence, so top rules are checked before bottom rules. Whenever there is a match, no more rules are tested, as the matching class is considered the predicted class.

## Rule Inference

The Miner component of SignatureMiner is designed to help users inspect signature collections and determine, from the observed tokens, the most appropriate rules. Rule matching is enabled in the miner component so users can test rules and determine whether they can be improved (as clustering still groups the rule with other signatures)

Miner component can be applied as many times and will be updated as soon as the rule file is changed. If no rule file is used, the miner will tokenize (or not) the signatures and return groups of raw normalized tokens.




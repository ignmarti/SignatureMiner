import re
import sys
import json
import hashlib

rules=[]

def applyRules(signature):
    global rules
    if rules is None:
    	return(signature)
    for rule in rules:
        if re.search(str(rule[0]), signature) is not None:
            return(rule[1])
    return(signature)

def process_input(element, split=False):
    elementAVs=element.get("av_labels", [])
    element["AV engines"]=[x[0] for x in elementAVs]
    ids=[]
    for x in elementAVs:
        item=x[1]
        cleanSign=applyRules(re.sub("[^a-z\.]*", "",item.lower()))
        if(split):
        	cleanSign=cleanSign.split(".")
        else: 
        	cleanSign=[cleanSign]
        ids.extend(cleanSign)
    element["malwareFamilies"]=ids
    return element

def hashMin(sset):
    hM=1e1000
    for element in sset:
        m=hashlib.sha1()
        m.update(element.encode("utf-8"))
        hM=min(hM, int(m.hexdigest(), 16))
    return hM

def computeShingles(text, k=5):
    return([text[i:min(i+k, len(text))] for i in range(len(text))])
    
def addMinHash(element, k=5):
    text=element
    sset=computeShingles(text, k=k)
    hM=hashMin(sset)
    return((str(hex(hM)), element))
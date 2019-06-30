#!/usr/bin/env python

class ESScript:
    DictA={
    "mappings": {
        "doc":{
            "properties": {
                "classInfo": {
                    "type": "text",
                    "fields": {
                        "keyword": {
                            "type": "keyword",
                            "ignore_above": 256
                        }
                    },
                    "analyzer": "ik_max_word",
                    "fielddata": "true"
                },
                "errorType": {
                    "type": "keyword"
                },
                "warnType": {
                    "type": "keyword"
                },
                "debugType": {
                    "type": "keyword"
                },
                "infoType": {
                    "type": "keyword"
                },
                "logDesc": {
                    "type": "text",
                    "fields": {
                        "keyword": {
                            "type": "keyword",
                            "ignore_above": 256
                        }
                    },
                    "analyzer": "ik_max_word",
                    "fielddata": "true"
                },
                "logLevel": {
                    "type": "keyword"
                },
                "logType": {
                    "type": "keyword"
                },
                "logResult": {
                    "type": "keyword"
                },
                "logUserName": {
                    "type": "keyword"
                },
                "logUserIp": {
                    "type": "keyword"
                },
                "machineIp": {
                    "type": "keyword"
                },
                "system": {
                    "type": "keyword"
                },
                "moduleName": {
                    "type": "keyword"
                },
                "operateType": {
                    "type": "keyword"
                },
                "logUserTrueName": {
                    "type": "keyword"
                }
            }
        }
    }
}
    DictB={
  "settings": {
    "analysis": {
      "analyzer": {
        "digital-number": {
          "type":"custom",
          "char_filter":["chinese_char_filter"],
          "tokenizer": "whitespace",
          "filter": [
            "lowercase","ngramfilter"
          ]
        }
      },
      "char_filter": {
          "chinese_char_filter": {
            "type": "pattern_replace",
            "pattern": "[\u4e00-\u9fa5]",
            "replacement": " "
          }
        },
      "filter": {
        "ngramfilter":{
          "type":"ngram",
          "min_gram": 1,
          "max_gram": 20
        }
      }
    }
  },
  "mappings": {
    "evidence":{
    "properties": {
      "text": {
        "type": "text",
        "fields":{
          "digit":{
            "type":"text",
            "analyzer":"digital-number"
          },
          "other":{
            "type":"text",
            "analyzer":"hanlp_nlp"
          }
        }
      }
    }
    }
  }
}

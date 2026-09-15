window.BENCHMARK_DATA = {
  "lastUpdate": 1789469339236,
  "repoUrl": "https://github.com/moov-io/signedxml",
  "entries": {
    "moov-io/signedxml": [
      {
        "commit": {
          "author": {
            "name": "Adam Shannon",
            "username": "adamdecaf",
            "email": "adamkshannon@gmail.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "1d2b0aa3c3729d2261d26d59c11fe4ec3db6ed01",
          "message": "ci: run XML encryption Go benchmarks in this repository (#141)",
          "timestamp": "2026-09-14T18:43:49Z",
          "url": "https://github.com/moov-io/signedxml/commit/1d2b0aa3c3729d2261d26d59c11fe4ec3db6ed01"
        },
        "date": 1789411705843,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkEncryptElement",
            "value": 5398,
            "unit": "ns/op\t    8600 B/op\t      23 allocs/op",
            "extra": "219420 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - ns/op",
            "value": 5398,
            "unit": "ns/op",
            "extra": "219420 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - B/op",
            "value": 8600,
            "unit": "B/op",
            "extra": "219420 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - allocs/op",
            "value": 23,
            "unit": "allocs/op",
            "extra": "219420 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement",
            "value": 13821,
            "unit": "ns/op\t   10400 B/op\t      27 allocs/op",
            "extra": "85370 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - ns/op",
            "value": 13821,
            "unit": "ns/op",
            "extra": "85370 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - B/op",
            "value": 10400,
            "unit": "B/op",
            "extra": "85370 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - allocs/op",
            "value": 27,
            "unit": "allocs/op",
            "extra": "85370 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt",
            "value": 179881,
            "unit": "ns/op\t   24176 B/op\t     118 allocs/op",
            "extra": "6444 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - ns/op",
            "value": 179881,
            "unit": "ns/op",
            "extra": "6444 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - B/op",
            "value": 24176,
            "unit": "B/op",
            "extra": "6444 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - allocs/op",
            "value": 118,
            "unit": "allocs/op",
            "extra": "6444 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement",
            "value": 104795,
            "unit": "ns/op\t    1617 B/op\t      24 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - ns/op",
            "value": 104795,
            "unit": "ns/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - B/op",
            "value": 1617,
            "unit": "B/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - allocs/op",
            "value": 24,
            "unit": "allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey",
            "value": 105192,
            "unit": "ns/op\t    3296 B/op\t      44 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - ns/op",
            "value": 105192,
            "unit": "ns/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - B/op",
            "value": 3296,
            "unit": "B/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - allocs/op",
            "value": 44,
            "unit": "allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap",
            "value": 1048,
            "unit": "ns/op\t     736 B/op\t       8 allocs/op",
            "extra": "1000000 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - ns/op",
            "value": 1048,
            "unit": "ns/op",
            "extra": "1000000 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - B/op",
            "value": 736,
            "unit": "B/op",
            "extra": "1000000 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "1000000 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap",
            "value": 1110,
            "unit": "ns/op\t     720 B/op\t       8 allocs/op",
            "extra": "1000000 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - ns/op",
            "value": 1110,
            "unit": "ns/op",
            "extra": "1000000 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - B/op",
            "value": 720,
            "unit": "B/op",
            "extra": "1000000 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "1000000 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt",
            "value": 918.5,
            "unit": "ns/op\t    2448 B/op\t       4 allocs/op",
            "extra": "1304805 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - ns/op",
            "value": 918.5,
            "unit": "ns/op",
            "extra": "1304805 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - B/op",
            "value": 2448,
            "unit": "B/op",
            "extra": "1304805 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - allocs/op",
            "value": 4,
            "unit": "allocs/op",
            "extra": "1304805 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline",
            "value": 111047,
            "unit": "ns/op\t   13432 B/op\t     117 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - ns/op",
            "value": 111047,
            "unit": "ns/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - B/op",
            "value": 13432,
            "unit": "B/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - allocs/op",
            "value": 117,
            "unit": "allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline",
            "value": 72584,
            "unit": "ns/op\t   15176 B/op\t     205 allocs/op",
            "extra": "16762 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - ns/op",
            "value": 72584,
            "unit": "ns/op",
            "extra": "16762 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - B/op",
            "value": 15176,
            "unit": "B/op",
            "extra": "16762 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - allocs/op",
            "value": 205,
            "unit": "allocs/op",
            "extra": "16762 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Adam Shannon",
            "username": "adamdecaf",
            "email": "adamkshannon@gmail.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "1d2b0aa3c3729d2261d26d59c11fe4ec3db6ed01",
          "message": "ci: run XML encryption Go benchmarks in this repository (#141)",
          "timestamp": "2026-09-14T18:43:49Z",
          "url": "https://github.com/moov-io/signedxml/commit/1d2b0aa3c3729d2261d26d59c11fe4ec3db6ed01"
        },
        "date": 1789469337327,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkEncryptElement",
            "value": 3226,
            "unit": "ns/op\t    8600 B/op\t      23 allocs/op",
            "extra": "369661 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - ns/op",
            "value": 3226,
            "unit": "ns/op",
            "extra": "369661 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - B/op",
            "value": 8600,
            "unit": "B/op",
            "extra": "369661 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - allocs/op",
            "value": 23,
            "unit": "allocs/op",
            "extra": "369661 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement",
            "value": 9216,
            "unit": "ns/op\t   10400 B/op\t      27 allocs/op",
            "extra": "134492 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - ns/op",
            "value": 9216,
            "unit": "ns/op",
            "extra": "134492 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - B/op",
            "value": 10400,
            "unit": "B/op",
            "extra": "134492 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - allocs/op",
            "value": 27,
            "unit": "allocs/op",
            "extra": "134492 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt",
            "value": 113911,
            "unit": "ns/op\t   24176 B/op\t     118 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - ns/op",
            "value": 113911,
            "unit": "ns/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - B/op",
            "value": 24176,
            "unit": "B/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - allocs/op",
            "value": 118,
            "unit": "allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement",
            "value": 62308,
            "unit": "ns/op\t    1617 B/op\t      24 allocs/op",
            "extra": "19291 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - ns/op",
            "value": 62308,
            "unit": "ns/op",
            "extra": "19291 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - B/op",
            "value": 1617,
            "unit": "B/op",
            "extra": "19291 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - allocs/op",
            "value": 24,
            "unit": "allocs/op",
            "extra": "19291 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey",
            "value": 63662,
            "unit": "ns/op\t    3296 B/op\t      44 allocs/op",
            "extra": "18283 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - ns/op",
            "value": 63662,
            "unit": "ns/op",
            "extra": "18283 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - B/op",
            "value": 3296,
            "unit": "B/op",
            "extra": "18283 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - allocs/op",
            "value": 44,
            "unit": "allocs/op",
            "extra": "18283 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap",
            "value": 784.4,
            "unit": "ns/op\t     736 B/op\t       8 allocs/op",
            "extra": "1528407 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - ns/op",
            "value": 784.4,
            "unit": "ns/op",
            "extra": "1528407 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - B/op",
            "value": 736,
            "unit": "B/op",
            "extra": "1528407 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "1528407 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap",
            "value": 789.4,
            "unit": "ns/op\t     720 B/op\t       8 allocs/op",
            "extra": "1458740 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - ns/op",
            "value": 789.4,
            "unit": "ns/op",
            "extra": "1458740 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - B/op",
            "value": 720,
            "unit": "B/op",
            "extra": "1458740 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "1458740 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt",
            "value": 581.7,
            "unit": "ns/op\t    2448 B/op\t       4 allocs/op",
            "extra": "2008971 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - ns/op",
            "value": 581.7,
            "unit": "ns/op",
            "extra": "2008971 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - B/op",
            "value": 2448,
            "unit": "B/op",
            "extra": "2008971 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - allocs/op",
            "value": 4,
            "unit": "allocs/op",
            "extra": "2008971 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline",
            "value": 65572,
            "unit": "ns/op\t   13432 B/op\t     117 allocs/op",
            "extra": "18336 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - ns/op",
            "value": 65572,
            "unit": "ns/op",
            "extra": "18336 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - B/op",
            "value": 13432,
            "unit": "B/op",
            "extra": "18336 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - allocs/op",
            "value": 117,
            "unit": "allocs/op",
            "extra": "18336 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline",
            "value": 41502,
            "unit": "ns/op\t   15176 B/op\t     205 allocs/op",
            "extra": "28754 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - ns/op",
            "value": 41502,
            "unit": "ns/op",
            "extra": "28754 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - B/op",
            "value": 15176,
            "unit": "B/op",
            "extra": "28754 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - allocs/op",
            "value": 205,
            "unit": "allocs/op",
            "extra": "28754 times\n4 procs"
          }
        ]
      }
    ]
  }
}
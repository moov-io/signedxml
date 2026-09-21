window.BENCHMARK_DATA = {
  "lastUpdate": 1789990792898,
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
      },
      {
        "commit": {
          "author": {
            "name": "renovate[bot]",
            "username": "renovate[bot]",
            "email": "29139614+renovate[bot]@users.noreply.github.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "ea62baacb44adc34905fb96bb7cede236f786977",
          "message": "chore(deps): update benchmark-action/github-action-benchmark action to v1.22.2 (#142)\n\nCo-authored-by: renovate[bot] <29139614+renovate[bot]@users.noreply.github.com>",
          "timestamp": "2026-09-15T19:53:26Z",
          "url": "https://github.com/moov-io/signedxml/commit/ea62baacb44adc34905fb96bb7cede236f786977"
        },
        "date": 1789555062080,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkEncryptElement",
            "value": 5697,
            "unit": "ns/op\t    8600 B/op\t      23 allocs/op",
            "extra": "211678 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - ns/op",
            "value": 5697,
            "unit": "ns/op",
            "extra": "211678 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - B/op",
            "value": 8600,
            "unit": "B/op",
            "extra": "211678 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - allocs/op",
            "value": 23,
            "unit": "allocs/op",
            "extra": "211678 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement",
            "value": 17420,
            "unit": "ns/op\t   10400 B/op\t      27 allocs/op",
            "extra": "67210 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - ns/op",
            "value": 17420,
            "unit": "ns/op",
            "extra": "67210 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - B/op",
            "value": 10400,
            "unit": "B/op",
            "extra": "67210 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - allocs/op",
            "value": 27,
            "unit": "allocs/op",
            "extra": "67210 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt",
            "value": 193649,
            "unit": "ns/op\t   24176 B/op\t     118 allocs/op",
            "extra": "6097 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - ns/op",
            "value": 193649,
            "unit": "ns/op",
            "extra": "6097 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - B/op",
            "value": 24176,
            "unit": "B/op",
            "extra": "6097 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - allocs/op",
            "value": 118,
            "unit": "allocs/op",
            "extra": "6097 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement",
            "value": 105685,
            "unit": "ns/op\t    1617 B/op\t      24 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - ns/op",
            "value": 105685,
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
            "value": 107346,
            "unit": "ns/op\t    3296 B/op\t      44 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - ns/op",
            "value": 107346,
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
            "value": 1232,
            "unit": "ns/op\t     736 B/op\t       8 allocs/op",
            "extra": "861854 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - ns/op",
            "value": 1232,
            "unit": "ns/op",
            "extra": "861854 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - B/op",
            "value": 736,
            "unit": "B/op",
            "extra": "861854 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "861854 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap",
            "value": 1245,
            "unit": "ns/op\t     720 B/op\t       8 allocs/op",
            "extra": "859741 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - ns/op",
            "value": 1245,
            "unit": "ns/op",
            "extra": "859741 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - B/op",
            "value": 720,
            "unit": "B/op",
            "extra": "859741 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "859741 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt",
            "value": 927,
            "unit": "ns/op\t    2448 B/op\t       4 allocs/op",
            "extra": "1291740 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - ns/op",
            "value": 927,
            "unit": "ns/op",
            "extra": "1291740 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - B/op",
            "value": 2448,
            "unit": "B/op",
            "extra": "1291740 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - allocs/op",
            "value": 4,
            "unit": "allocs/op",
            "extra": "1291740 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline",
            "value": 114645,
            "unit": "ns/op\t   13432 B/op\t     117 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - ns/op",
            "value": 114645,
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
            "value": 73987,
            "unit": "ns/op\t   15176 B/op\t     205 allocs/op",
            "extra": "16147 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - ns/op",
            "value": 73987,
            "unit": "ns/op",
            "extra": "16147 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - B/op",
            "value": 15176,
            "unit": "B/op",
            "extra": "16147 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - allocs/op",
            "value": 205,
            "unit": "allocs/op",
            "extra": "16147 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "renovate[bot]",
            "username": "renovate[bot]",
            "email": "29139614+renovate[bot]@users.noreply.github.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "ea62baacb44adc34905fb96bb7cede236f786977",
          "message": "chore(deps): update benchmark-action/github-action-benchmark action to v1.22.2 (#142)\n\nCo-authored-by: renovate[bot] <29139614+renovate[bot]@users.noreply.github.com>",
          "timestamp": "2026-09-15T19:53:26Z",
          "url": "https://github.com/moov-io/signedxml/commit/ea62baacb44adc34905fb96bb7cede236f786977"
        },
        "date": 1789642017142,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkEncryptElement",
            "value": 6147,
            "unit": "ns/op\t    8600 B/op\t      23 allocs/op",
            "extra": "205402 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - ns/op",
            "value": 6147,
            "unit": "ns/op",
            "extra": "205402 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - B/op",
            "value": 8600,
            "unit": "B/op",
            "extra": "205402 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - allocs/op",
            "value": 23,
            "unit": "allocs/op",
            "extra": "205402 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement",
            "value": 17099,
            "unit": "ns/op\t   10400 B/op\t      27 allocs/op",
            "extra": "71718 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - ns/op",
            "value": 17099,
            "unit": "ns/op",
            "extra": "71718 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - B/op",
            "value": 10400,
            "unit": "B/op",
            "extra": "71718 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - allocs/op",
            "value": 27,
            "unit": "allocs/op",
            "extra": "71718 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt",
            "value": 191270,
            "unit": "ns/op\t   24176 B/op\t     118 allocs/op",
            "extra": "6037 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - ns/op",
            "value": 191270,
            "unit": "ns/op",
            "extra": "6037 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - B/op",
            "value": 24176,
            "unit": "B/op",
            "extra": "6037 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - allocs/op",
            "value": 118,
            "unit": "allocs/op",
            "extra": "6037 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement",
            "value": 106223,
            "unit": "ns/op\t    1617 B/op\t      24 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - ns/op",
            "value": 106223,
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
            "value": 110462,
            "unit": "ns/op\t    3296 B/op\t      44 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - ns/op",
            "value": 110462,
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
            "value": 1227,
            "unit": "ns/op\t     736 B/op\t       8 allocs/op",
            "extra": "855079 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - ns/op",
            "value": 1227,
            "unit": "ns/op",
            "extra": "855079 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - B/op",
            "value": 736,
            "unit": "B/op",
            "extra": "855079 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "855079 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap",
            "value": 1251,
            "unit": "ns/op\t     720 B/op\t       8 allocs/op",
            "extra": "879708 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - ns/op",
            "value": 1251,
            "unit": "ns/op",
            "extra": "879708 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - B/op",
            "value": 720,
            "unit": "B/op",
            "extra": "879708 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "879708 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt",
            "value": 909.4,
            "unit": "ns/op\t    2448 B/op\t       4 allocs/op",
            "extra": "1322282 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - ns/op",
            "value": 909.4,
            "unit": "ns/op",
            "extra": "1322282 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - B/op",
            "value": 2448,
            "unit": "B/op",
            "extra": "1322282 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - allocs/op",
            "value": 4,
            "unit": "allocs/op",
            "extra": "1322282 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline",
            "value": 117067,
            "unit": "ns/op\t   13432 B/op\t     117 allocs/op",
            "extra": "9855 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - ns/op",
            "value": 117067,
            "unit": "ns/op",
            "extra": "9855 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - B/op",
            "value": 13432,
            "unit": "B/op",
            "extra": "9855 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - allocs/op",
            "value": 117,
            "unit": "allocs/op",
            "extra": "9855 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline",
            "value": 74010,
            "unit": "ns/op\t   15176 B/op\t     205 allocs/op",
            "extra": "16113 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - ns/op",
            "value": 74010,
            "unit": "ns/op",
            "extra": "16113 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - B/op",
            "value": 15176,
            "unit": "B/op",
            "extra": "16113 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - allocs/op",
            "value": 205,
            "unit": "allocs/op",
            "extra": "16113 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "renovate[bot]",
            "username": "renovate[bot]",
            "email": "29139614+renovate[bot]@users.noreply.github.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "ea62baacb44adc34905fb96bb7cede236f786977",
          "message": "chore(deps): update benchmark-action/github-action-benchmark action to v1.22.2 (#142)\n\nCo-authored-by: renovate[bot] <29139614+renovate[bot]@users.noreply.github.com>",
          "timestamp": "2026-09-15T19:53:26Z",
          "url": "https://github.com/moov-io/signedxml/commit/ea62baacb44adc34905fb96bb7cede236f786977"
        },
        "date": 1789726936099,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkEncryptElement",
            "value": 4583,
            "unit": "ns/op\t    8600 B/op\t      23 allocs/op",
            "extra": "261470 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - ns/op",
            "value": 4583,
            "unit": "ns/op",
            "extra": "261470 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - B/op",
            "value": 8600,
            "unit": "B/op",
            "extra": "261470 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - allocs/op",
            "value": 23,
            "unit": "allocs/op",
            "extra": "261470 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement",
            "value": 12694,
            "unit": "ns/op\t   10400 B/op\t      27 allocs/op",
            "extra": "93051 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - ns/op",
            "value": 12694,
            "unit": "ns/op",
            "extra": "93051 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - B/op",
            "value": 10400,
            "unit": "B/op",
            "extra": "93051 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - allocs/op",
            "value": 27,
            "unit": "allocs/op",
            "extra": "93051 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt",
            "value": 156072,
            "unit": "ns/op\t   24176 B/op\t     118 allocs/op",
            "extra": "7336 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - ns/op",
            "value": 156072,
            "unit": "ns/op",
            "extra": "7336 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - B/op",
            "value": 24176,
            "unit": "B/op",
            "extra": "7336 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - allocs/op",
            "value": 118,
            "unit": "allocs/op",
            "extra": "7336 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement",
            "value": 90568,
            "unit": "ns/op\t    1617 B/op\t      24 allocs/op",
            "extra": "13321 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - ns/op",
            "value": 90568,
            "unit": "ns/op",
            "extra": "13321 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - B/op",
            "value": 1617,
            "unit": "B/op",
            "extra": "13321 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - allocs/op",
            "value": 24,
            "unit": "allocs/op",
            "extra": "13321 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey",
            "value": 91293,
            "unit": "ns/op\t    3296 B/op\t      44 allocs/op",
            "extra": "13140 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - ns/op",
            "value": 91293,
            "unit": "ns/op",
            "extra": "13140 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - B/op",
            "value": 3296,
            "unit": "B/op",
            "extra": "13140 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - allocs/op",
            "value": 44,
            "unit": "allocs/op",
            "extra": "13140 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap",
            "value": 971.1,
            "unit": "ns/op\t     736 B/op\t       8 allocs/op",
            "extra": "1218462 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - ns/op",
            "value": 971.1,
            "unit": "ns/op",
            "extra": "1218462 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - B/op",
            "value": 736,
            "unit": "B/op",
            "extra": "1218462 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "1218462 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap",
            "value": 977.5,
            "unit": "ns/op\t     720 B/op\t       8 allocs/op",
            "extra": "1229534 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - ns/op",
            "value": 977.5,
            "unit": "ns/op",
            "extra": "1229534 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - B/op",
            "value": 720,
            "unit": "B/op",
            "extra": "1229534 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "1229534 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt",
            "value": 693.8,
            "unit": "ns/op\t    2448 B/op\t       4 allocs/op",
            "extra": "1717185 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - ns/op",
            "value": 693.8,
            "unit": "ns/op",
            "extra": "1717185 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - B/op",
            "value": 2448,
            "unit": "B/op",
            "extra": "1717185 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - allocs/op",
            "value": 4,
            "unit": "allocs/op",
            "extra": "1717185 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline",
            "value": 96004,
            "unit": "ns/op\t   13432 B/op\t     117 allocs/op",
            "extra": "12464 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - ns/op",
            "value": 96004,
            "unit": "ns/op",
            "extra": "12464 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - B/op",
            "value": 13432,
            "unit": "B/op",
            "extra": "12464 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - allocs/op",
            "value": 117,
            "unit": "allocs/op",
            "extra": "12464 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline",
            "value": 59702,
            "unit": "ns/op\t   15176 B/op\t     205 allocs/op",
            "extra": "20120 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - ns/op",
            "value": 59702,
            "unit": "ns/op",
            "extra": "20120 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - B/op",
            "value": 15176,
            "unit": "B/op",
            "extra": "20120 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - allocs/op",
            "value": 205,
            "unit": "allocs/op",
            "extra": "20120 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "renovate[bot]",
            "username": "renovate[bot]",
            "email": "29139614+renovate[bot]@users.noreply.github.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "28ab2c8b03dec0cc8eb988742b45c50126ef96c3",
          "message": "chore(deps): update github/codeql-action action to v4.38.1 (#143)\n\nCo-authored-by: renovate[bot] <29139614+renovate[bot]@users.noreply.github.com>",
          "timestamp": "2026-09-18T14:59:24Z",
          "url": "https://github.com/moov-io/signedxml/commit/28ab2c8b03dec0cc8eb988742b45c50126ef96c3"
        },
        "date": 1789812334238,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkEncryptElement",
            "value": 5831,
            "unit": "ns/op\t    8600 B/op\t      23 allocs/op",
            "extra": "205428 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - ns/op",
            "value": 5831,
            "unit": "ns/op",
            "extra": "205428 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - B/op",
            "value": 8600,
            "unit": "B/op",
            "extra": "205428 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - allocs/op",
            "value": 23,
            "unit": "allocs/op",
            "extra": "205428 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement",
            "value": 16555,
            "unit": "ns/op\t   10400 B/op\t      27 allocs/op",
            "extra": "72792 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - ns/op",
            "value": 16555,
            "unit": "ns/op",
            "extra": "72792 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - B/op",
            "value": 10400,
            "unit": "B/op",
            "extra": "72792 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - allocs/op",
            "value": 27,
            "unit": "allocs/op",
            "extra": "72792 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt",
            "value": 185945,
            "unit": "ns/op\t   24176 B/op\t     118 allocs/op",
            "extra": "6184 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - ns/op",
            "value": 185945,
            "unit": "ns/op",
            "extra": "6184 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - B/op",
            "value": 24176,
            "unit": "B/op",
            "extra": "6184 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - allocs/op",
            "value": 118,
            "unit": "allocs/op",
            "extra": "6184 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement",
            "value": 105958,
            "unit": "ns/op\t    1617 B/op\t      24 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - ns/op",
            "value": 105958,
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
            "value": 107628,
            "unit": "ns/op\t    3296 B/op\t      44 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - ns/op",
            "value": 107628,
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
            "value": 1228,
            "unit": "ns/op\t     736 B/op\t       8 allocs/op",
            "extra": "861322 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - ns/op",
            "value": 1228,
            "unit": "ns/op",
            "extra": "861322 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - B/op",
            "value": 736,
            "unit": "B/op",
            "extra": "861322 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "861322 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap",
            "value": 1243,
            "unit": "ns/op\t     720 B/op\t       8 allocs/op",
            "extra": "878230 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - ns/op",
            "value": 1243,
            "unit": "ns/op",
            "extra": "878230 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - B/op",
            "value": 720,
            "unit": "B/op",
            "extra": "878230 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "878230 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt",
            "value": 911.8,
            "unit": "ns/op\t    2448 B/op\t       4 allocs/op",
            "extra": "1275292 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - ns/op",
            "value": 911.8,
            "unit": "ns/op",
            "extra": "1275292 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - B/op",
            "value": 2448,
            "unit": "B/op",
            "extra": "1275292 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - allocs/op",
            "value": 4,
            "unit": "allocs/op",
            "extra": "1275292 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline",
            "value": 114085,
            "unit": "ns/op\t   13432 B/op\t     117 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - ns/op",
            "value": 114085,
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
            "value": 74132,
            "unit": "ns/op\t   15176 B/op\t     205 allocs/op",
            "extra": "16216 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - ns/op",
            "value": 74132,
            "unit": "ns/op",
            "extra": "16216 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - B/op",
            "value": 15176,
            "unit": "B/op",
            "extra": "16216 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - allocs/op",
            "value": 205,
            "unit": "allocs/op",
            "extra": "16216 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "renovate[bot]",
            "username": "renovate[bot]",
            "email": "29139614+renovate[bot]@users.noreply.github.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "28ab2c8b03dec0cc8eb988742b45c50126ef96c3",
          "message": "chore(deps): update github/codeql-action action to v4.38.1 (#143)\n\nCo-authored-by: renovate[bot] <29139614+renovate[bot]@users.noreply.github.com>",
          "timestamp": "2026-09-18T14:59:24Z",
          "url": "https://github.com/moov-io/signedxml/commit/28ab2c8b03dec0cc8eb988742b45c50126ef96c3"
        },
        "date": 1789899839510,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkEncryptElement",
            "value": 5717,
            "unit": "ns/op\t    8600 B/op\t      23 allocs/op",
            "extra": "217135 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - ns/op",
            "value": 5717,
            "unit": "ns/op",
            "extra": "217135 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - B/op",
            "value": 8600,
            "unit": "B/op",
            "extra": "217135 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - allocs/op",
            "value": 23,
            "unit": "allocs/op",
            "extra": "217135 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement",
            "value": 14056,
            "unit": "ns/op\t   10400 B/op\t      27 allocs/op",
            "extra": "86349 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - ns/op",
            "value": 14056,
            "unit": "ns/op",
            "extra": "86349 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - B/op",
            "value": 10400,
            "unit": "B/op",
            "extra": "86349 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - allocs/op",
            "value": 27,
            "unit": "allocs/op",
            "extra": "86349 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt",
            "value": 179674,
            "unit": "ns/op\t   24176 B/op\t     118 allocs/op",
            "extra": "6471 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - ns/op",
            "value": 179674,
            "unit": "ns/op",
            "extra": "6471 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - B/op",
            "value": 24176,
            "unit": "B/op",
            "extra": "6471 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - allocs/op",
            "value": 118,
            "unit": "allocs/op",
            "extra": "6471 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement",
            "value": 103035,
            "unit": "ns/op\t    1617 B/op\t      24 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - ns/op",
            "value": 103035,
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
            "value": 104488,
            "unit": "ns/op\t    3296 B/op\t      44 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - ns/op",
            "value": 104488,
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
            "value": 1050,
            "unit": "ns/op\t     736 B/op\t       8 allocs/op",
            "extra": "959312 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - ns/op",
            "value": 1050,
            "unit": "ns/op",
            "extra": "959312 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - B/op",
            "value": 736,
            "unit": "B/op",
            "extra": "959312 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "959312 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap",
            "value": 1092,
            "unit": "ns/op\t     720 B/op\t       8 allocs/op",
            "extra": "998391 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - ns/op",
            "value": 1092,
            "unit": "ns/op",
            "extra": "998391 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - B/op",
            "value": 720,
            "unit": "B/op",
            "extra": "998391 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "998391 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt",
            "value": 939,
            "unit": "ns/op\t    2448 B/op\t       4 allocs/op",
            "extra": "1270234 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - ns/op",
            "value": 939,
            "unit": "ns/op",
            "extra": "1270234 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - B/op",
            "value": 2448,
            "unit": "B/op",
            "extra": "1270234 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - allocs/op",
            "value": 4,
            "unit": "allocs/op",
            "extra": "1270234 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline",
            "value": 111199,
            "unit": "ns/op\t   13432 B/op\t     117 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - ns/op",
            "value": 111199,
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
            "value": 71993,
            "unit": "ns/op\t   15176 B/op\t     205 allocs/op",
            "extra": "16694 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - ns/op",
            "value": 71993,
            "unit": "ns/op",
            "extra": "16694 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - B/op",
            "value": 15176,
            "unit": "B/op",
            "extra": "16694 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - allocs/op",
            "value": 205,
            "unit": "allocs/op",
            "extra": "16694 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "renovate[bot]",
            "username": "renovate[bot]",
            "email": "29139614+renovate[bot]@users.noreply.github.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "28ab2c8b03dec0cc8eb988742b45c50126ef96c3",
          "message": "chore(deps): update github/codeql-action action to v4.38.1 (#143)\n\nCo-authored-by: renovate[bot] <29139614+renovate[bot]@users.noreply.github.com>",
          "timestamp": "2026-09-18T14:59:24Z",
          "url": "https://github.com/moov-io/signedxml/commit/28ab2c8b03dec0cc8eb988742b45c50126ef96c3"
        },
        "date": 1789990791612,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkEncryptElement",
            "value": 5689,
            "unit": "ns/op\t    8600 B/op\t      23 allocs/op",
            "extra": "208522 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - ns/op",
            "value": 5689,
            "unit": "ns/op",
            "extra": "208522 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - B/op",
            "value": 8600,
            "unit": "B/op",
            "extra": "208522 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - allocs/op",
            "value": 23,
            "unit": "allocs/op",
            "extra": "208522 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement",
            "value": 16418,
            "unit": "ns/op\t   10400 B/op\t      27 allocs/op",
            "extra": "72651 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - ns/op",
            "value": 16418,
            "unit": "ns/op",
            "extra": "72651 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - B/op",
            "value": 10400,
            "unit": "B/op",
            "extra": "72651 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - allocs/op",
            "value": 27,
            "unit": "allocs/op",
            "extra": "72651 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt",
            "value": 185768,
            "unit": "ns/op\t   24176 B/op\t     118 allocs/op",
            "extra": "6057 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - ns/op",
            "value": 185768,
            "unit": "ns/op",
            "extra": "6057 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - B/op",
            "value": 24176,
            "unit": "B/op",
            "extra": "6057 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - allocs/op",
            "value": 118,
            "unit": "allocs/op",
            "extra": "6057 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement",
            "value": 109675,
            "unit": "ns/op\t    1617 B/op\t      24 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - ns/op",
            "value": 109675,
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
            "value": 107315,
            "unit": "ns/op\t    3296 B/op\t      44 allocs/op",
            "extra": "11025 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - ns/op",
            "value": 107315,
            "unit": "ns/op",
            "extra": "11025 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - B/op",
            "value": 3296,
            "unit": "B/op",
            "extra": "11025 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - allocs/op",
            "value": 44,
            "unit": "allocs/op",
            "extra": "11025 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap",
            "value": 1222,
            "unit": "ns/op\t     736 B/op\t       8 allocs/op",
            "extra": "867772 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - ns/op",
            "value": 1222,
            "unit": "ns/op",
            "extra": "867772 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - B/op",
            "value": 736,
            "unit": "B/op",
            "extra": "867772 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "867772 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap",
            "value": 1249,
            "unit": "ns/op\t     720 B/op\t       8 allocs/op",
            "extra": "877230 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - ns/op",
            "value": 1249,
            "unit": "ns/op",
            "extra": "877230 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - B/op",
            "value": 720,
            "unit": "B/op",
            "extra": "877230 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "877230 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt",
            "value": 908.4,
            "unit": "ns/op\t    2448 B/op\t       4 allocs/op",
            "extra": "1315761 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - ns/op",
            "value": 908.4,
            "unit": "ns/op",
            "extra": "1315761 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - B/op",
            "value": 2448,
            "unit": "B/op",
            "extra": "1315761 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - allocs/op",
            "value": 4,
            "unit": "allocs/op",
            "extra": "1315761 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline",
            "value": 113776,
            "unit": "ns/op\t   13432 B/op\t     117 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - ns/op",
            "value": 113776,
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
            "value": 73757,
            "unit": "ns/op\t   15176 B/op\t     205 allocs/op",
            "extra": "16422 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - ns/op",
            "value": 73757,
            "unit": "ns/op",
            "extra": "16422 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - B/op",
            "value": 15176,
            "unit": "B/op",
            "extra": "16422 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - allocs/op",
            "value": 205,
            "unit": "allocs/op",
            "extra": "16422 times\n4 procs"
          }
        ]
      }
    ]
  }
}
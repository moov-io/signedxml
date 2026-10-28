window.BENCHMARK_DATA = {
  "lastUpdate": 1793188656859,
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
        "date": 1790073860697,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkEncryptElement",
            "value": 7466,
            "unit": "ns/op\t    8600 B/op\t      23 allocs/op",
            "extra": "155473 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - ns/op",
            "value": 7466,
            "unit": "ns/op",
            "extra": "155473 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - B/op",
            "value": 8600,
            "unit": "B/op",
            "extra": "155473 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - allocs/op",
            "value": 23,
            "unit": "allocs/op",
            "extra": "155473 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement",
            "value": 19790,
            "unit": "ns/op\t   10400 B/op\t      27 allocs/op",
            "extra": "57205 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - ns/op",
            "value": 19790,
            "unit": "ns/op",
            "extra": "57205 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - B/op",
            "value": 10400,
            "unit": "B/op",
            "extra": "57205 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - allocs/op",
            "value": 27,
            "unit": "allocs/op",
            "extra": "57205 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt",
            "value": 184308,
            "unit": "ns/op\t   24176 B/op\t     118 allocs/op",
            "extra": "6432 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - ns/op",
            "value": 184308,
            "unit": "ns/op",
            "extra": "6432 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - B/op",
            "value": 24176,
            "unit": "B/op",
            "extra": "6432 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - allocs/op",
            "value": 118,
            "unit": "allocs/op",
            "extra": "6432 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement",
            "value": 105831,
            "unit": "ns/op\t    1617 B/op\t      24 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - ns/op",
            "value": 105831,
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
            "value": 107606,
            "unit": "ns/op\t    3296 B/op\t      44 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - ns/op",
            "value": 107606,
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
            "extra": "872042 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - ns/op",
            "value": 1227,
            "unit": "ns/op",
            "extra": "872042 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - B/op",
            "value": 736,
            "unit": "B/op",
            "extra": "872042 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "872042 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap",
            "value": 1234,
            "unit": "ns/op\t     720 B/op\t       8 allocs/op",
            "extra": "865836 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - ns/op",
            "value": 1234,
            "unit": "ns/op",
            "extra": "865836 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - B/op",
            "value": 720,
            "unit": "B/op",
            "extra": "865836 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "865836 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt",
            "value": 894.1,
            "unit": "ns/op\t    2448 B/op\t       4 allocs/op",
            "extra": "1346178 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - ns/op",
            "value": 894.1,
            "unit": "ns/op",
            "extra": "1346178 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - B/op",
            "value": 2448,
            "unit": "B/op",
            "extra": "1346178 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - allocs/op",
            "value": 4,
            "unit": "allocs/op",
            "extra": "1346178 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline",
            "value": 113761,
            "unit": "ns/op\t   13432 B/op\t     117 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - ns/op",
            "value": 113761,
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
            "value": 73526,
            "unit": "ns/op\t   15176 B/op\t     205 allocs/op",
            "extra": "16048 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - ns/op",
            "value": 73526,
            "unit": "ns/op",
            "extra": "16048 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - B/op",
            "value": 15176,
            "unit": "B/op",
            "extra": "16048 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - allocs/op",
            "value": 205,
            "unit": "allocs/op",
            "extra": "16048 times\n4 procs"
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
        "date": 1790159704267,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkEncryptElement",
            "value": 5415,
            "unit": "ns/op\t    8600 B/op\t      23 allocs/op",
            "extra": "218770 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - ns/op",
            "value": 5415,
            "unit": "ns/op",
            "extra": "218770 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - B/op",
            "value": 8600,
            "unit": "B/op",
            "extra": "218770 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - allocs/op",
            "value": 23,
            "unit": "allocs/op",
            "extra": "218770 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement",
            "value": 14000,
            "unit": "ns/op\t   10400 B/op\t      27 allocs/op",
            "extra": "86664 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - ns/op",
            "value": 14000,
            "unit": "ns/op",
            "extra": "86664 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - B/op",
            "value": 10400,
            "unit": "B/op",
            "extra": "86664 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - allocs/op",
            "value": 27,
            "unit": "allocs/op",
            "extra": "86664 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt",
            "value": 177467,
            "unit": "ns/op\t   24176 B/op\t     118 allocs/op",
            "extra": "6235 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - ns/op",
            "value": 177467,
            "unit": "ns/op",
            "extra": "6235 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - B/op",
            "value": 24176,
            "unit": "B/op",
            "extra": "6235 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - allocs/op",
            "value": 118,
            "unit": "allocs/op",
            "extra": "6235 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement",
            "value": 103627,
            "unit": "ns/op\t    1617 B/op\t      24 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - ns/op",
            "value": 103627,
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
            "value": 104896,
            "unit": "ns/op\t    3296 B/op\t      44 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - ns/op",
            "value": 104896,
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
            "value": 1047,
            "unit": "ns/op\t     736 B/op\t       8 allocs/op",
            "extra": "963759 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - ns/op",
            "value": 1047,
            "unit": "ns/op",
            "extra": "963759 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - B/op",
            "value": 736,
            "unit": "B/op",
            "extra": "963759 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "963759 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap",
            "value": 1077,
            "unit": "ns/op\t     720 B/op\t       8 allocs/op",
            "extra": "1000000 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - ns/op",
            "value": 1077,
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
            "value": 905,
            "unit": "ns/op\t    2448 B/op\t       4 allocs/op",
            "extra": "1328434 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - ns/op",
            "value": 905,
            "unit": "ns/op",
            "extra": "1328434 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - B/op",
            "value": 2448,
            "unit": "B/op",
            "extra": "1328434 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - allocs/op",
            "value": 4,
            "unit": "allocs/op",
            "extra": "1328434 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline",
            "value": 110360,
            "unit": "ns/op\t   13432 B/op\t     117 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - ns/op",
            "value": 110360,
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
            "value": 70261,
            "unit": "ns/op\t   15176 B/op\t     205 allocs/op",
            "extra": "17037 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - ns/op",
            "value": 70261,
            "unit": "ns/op",
            "extra": "17037 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - B/op",
            "value": 15176,
            "unit": "B/op",
            "extra": "17037 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - allocs/op",
            "value": 205,
            "unit": "allocs/op",
            "extra": "17037 times\n4 procs"
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
          "id": "a8a1f1fb89b72a06c104f8f6480cec52e7eb2757",
          "message": "fix(deps): update module github.com/beevik/etree to v1.8.1 (#144)\n\nCo-authored-by: renovate[bot] <29139614+renovate[bot]@users.noreply.github.com>",
          "timestamp": "2026-09-24T06:15:13Z",
          "url": "https://github.com/moov-io/signedxml/commit/a8a1f1fb89b72a06c104f8f6480cec52e7eb2757"
        },
        "date": 1790247238366,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkEncryptElement",
            "value": 5544,
            "unit": "ns/op\t    8600 B/op\t      23 allocs/op",
            "extra": "220561 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - ns/op",
            "value": 5544,
            "unit": "ns/op",
            "extra": "220561 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - B/op",
            "value": 8600,
            "unit": "B/op",
            "extra": "220561 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - allocs/op",
            "value": 23,
            "unit": "allocs/op",
            "extra": "220561 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement",
            "value": 16124,
            "unit": "ns/op\t   10400 B/op\t      27 allocs/op",
            "extra": "73182 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - ns/op",
            "value": 16124,
            "unit": "ns/op",
            "extra": "73182 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - B/op",
            "value": 10400,
            "unit": "B/op",
            "extra": "73182 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - allocs/op",
            "value": 27,
            "unit": "allocs/op",
            "extra": "73182 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt",
            "value": 184378,
            "unit": "ns/op\t   24176 B/op\t     118 allocs/op",
            "extra": "6326 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - ns/op",
            "value": 184378,
            "unit": "ns/op",
            "extra": "6326 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - B/op",
            "value": 24176,
            "unit": "B/op",
            "extra": "6326 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - allocs/op",
            "value": 118,
            "unit": "allocs/op",
            "extra": "6326 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement",
            "value": 105387,
            "unit": "ns/op\t    1617 B/op\t      24 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - ns/op",
            "value": 105387,
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
            "value": 106675,
            "unit": "ns/op\t    3296 B/op\t      44 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - ns/op",
            "value": 106675,
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
            "value": 1212,
            "unit": "ns/op\t     736 B/op\t       8 allocs/op",
            "extra": "891045 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - ns/op",
            "value": 1212,
            "unit": "ns/op",
            "extra": "891045 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - B/op",
            "value": 736,
            "unit": "B/op",
            "extra": "891045 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "891045 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap",
            "value": 1235,
            "unit": "ns/op\t     720 B/op\t       8 allocs/op",
            "extra": "865708 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - ns/op",
            "value": 1235,
            "unit": "ns/op",
            "extra": "865708 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - B/op",
            "value": 720,
            "unit": "B/op",
            "extra": "865708 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "865708 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt",
            "value": 882.2,
            "unit": "ns/op\t    2448 B/op\t       4 allocs/op",
            "extra": "1345035 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - ns/op",
            "value": 882.2,
            "unit": "ns/op",
            "extra": "1345035 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - B/op",
            "value": 2448,
            "unit": "B/op",
            "extra": "1345035 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - allocs/op",
            "value": 4,
            "unit": "allocs/op",
            "extra": "1345035 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline",
            "value": 113645,
            "unit": "ns/op\t   13432 B/op\t     117 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - ns/op",
            "value": 113645,
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
            "value": 72381,
            "unit": "ns/op\t   15176 B/op\t     205 allocs/op",
            "extra": "16500 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - ns/op",
            "value": 72381,
            "unit": "ns/op",
            "extra": "16500 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - B/op",
            "value": 15176,
            "unit": "B/op",
            "extra": "16500 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - allocs/op",
            "value": 205,
            "unit": "allocs/op",
            "extra": "16500 times\n4 procs"
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
          "id": "6d62995f8cfde374ec1d4ebfaa7a76be0bf48e58",
          "message": "chore(deps): update github/codeql-action action to v4.38.2 (#145)\n\nCo-authored-by: renovate[bot] <29139614+renovate[bot]@users.noreply.github.com>",
          "timestamp": "2026-09-25T01:19:08Z",
          "url": "https://github.com/moov-io/signedxml/commit/6d62995f8cfde374ec1d4ebfaa7a76be0bf48e58"
        },
        "date": 1790333788669,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkEncryptElement",
            "value": 8128,
            "unit": "ns/op\t    8600 B/op\t      23 allocs/op",
            "extra": "153190 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - ns/op",
            "value": 8128,
            "unit": "ns/op",
            "extra": "153190 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - B/op",
            "value": 8600,
            "unit": "B/op",
            "extra": "153190 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - allocs/op",
            "value": 23,
            "unit": "allocs/op",
            "extra": "153190 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement",
            "value": 16848,
            "unit": "ns/op\t   10400 B/op\t      27 allocs/op",
            "extra": "62665 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - ns/op",
            "value": 16848,
            "unit": "ns/op",
            "extra": "62665 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - B/op",
            "value": 10400,
            "unit": "B/op",
            "extra": "62665 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - allocs/op",
            "value": 27,
            "unit": "allocs/op",
            "extra": "62665 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt",
            "value": 185505,
            "unit": "ns/op\t   24176 B/op\t     118 allocs/op",
            "extra": "6195 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - ns/op",
            "value": 185505,
            "unit": "ns/op",
            "extra": "6195 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - B/op",
            "value": 24176,
            "unit": "B/op",
            "extra": "6195 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - allocs/op",
            "value": 118,
            "unit": "allocs/op",
            "extra": "6195 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement",
            "value": 105601,
            "unit": "ns/op\t    1617 B/op\t      24 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - ns/op",
            "value": 105601,
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
            "value": 106710,
            "unit": "ns/op\t    3296 B/op\t      44 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - ns/op",
            "value": 106710,
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
            "value": 1218,
            "unit": "ns/op\t     736 B/op\t       8 allocs/op",
            "extra": "858964 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - ns/op",
            "value": 1218,
            "unit": "ns/op",
            "extra": "858964 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - B/op",
            "value": 736,
            "unit": "B/op",
            "extra": "858964 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "858964 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap",
            "value": 1239,
            "unit": "ns/op\t     720 B/op\t       8 allocs/op",
            "extra": "868438 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - ns/op",
            "value": 1239,
            "unit": "ns/op",
            "extra": "868438 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - B/op",
            "value": 720,
            "unit": "B/op",
            "extra": "868438 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "868438 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt",
            "value": 884,
            "unit": "ns/op\t    2448 B/op\t       4 allocs/op",
            "extra": "1358696 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - ns/op",
            "value": 884,
            "unit": "ns/op",
            "extra": "1358696 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - B/op",
            "value": 2448,
            "unit": "B/op",
            "extra": "1358696 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - allocs/op",
            "value": 4,
            "unit": "allocs/op",
            "extra": "1358696 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline",
            "value": 113999,
            "unit": "ns/op\t   13432 B/op\t     117 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - ns/op",
            "value": 113999,
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
            "value": 73613,
            "unit": "ns/op\t   15176 B/op\t     205 allocs/op",
            "extra": "15981 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - ns/op",
            "value": 73613,
            "unit": "ns/op",
            "extra": "15981 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - B/op",
            "value": 15176,
            "unit": "B/op",
            "extra": "15981 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - allocs/op",
            "value": 205,
            "unit": "allocs/op",
            "extra": "15981 times\n4 procs"
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
          "id": "6d62995f8cfde374ec1d4ebfaa7a76be0bf48e58",
          "message": "chore(deps): update github/codeql-action action to v4.38.2 (#145)\n\nCo-authored-by: renovate[bot] <29139614+renovate[bot]@users.noreply.github.com>",
          "timestamp": "2026-09-25T01:19:08Z",
          "url": "https://github.com/moov-io/signedxml/commit/6d62995f8cfde374ec1d4ebfaa7a76be0bf48e58"
        },
        "date": 1790419008273,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkEncryptElement",
            "value": 5916,
            "unit": "ns/op\t    8600 B/op\t      23 allocs/op",
            "extra": "206985 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - ns/op",
            "value": 5916,
            "unit": "ns/op",
            "extra": "206985 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - B/op",
            "value": 8600,
            "unit": "B/op",
            "extra": "206985 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - allocs/op",
            "value": 23,
            "unit": "allocs/op",
            "extra": "206985 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement",
            "value": 18712,
            "unit": "ns/op\t   10400 B/op\t      27 allocs/op",
            "extra": "62893 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - ns/op",
            "value": 18712,
            "unit": "ns/op",
            "extra": "62893 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - B/op",
            "value": 10400,
            "unit": "B/op",
            "extra": "62893 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - allocs/op",
            "value": 27,
            "unit": "allocs/op",
            "extra": "62893 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt",
            "value": 182910,
            "unit": "ns/op\t   24176 B/op\t     118 allocs/op",
            "extra": "6213 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - ns/op",
            "value": 182910,
            "unit": "ns/op",
            "extra": "6213 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - B/op",
            "value": 24176,
            "unit": "B/op",
            "extra": "6213 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - allocs/op",
            "value": 118,
            "unit": "allocs/op",
            "extra": "6213 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement",
            "value": 105253,
            "unit": "ns/op\t    1617 B/op\t      24 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - ns/op",
            "value": 105253,
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
            "value": 106587,
            "unit": "ns/op\t    3296 B/op\t      44 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - ns/op",
            "value": 106587,
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
            "value": 1266,
            "unit": "ns/op\t     736 B/op\t       8 allocs/op",
            "extra": "877296 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - ns/op",
            "value": 1266,
            "unit": "ns/op",
            "extra": "877296 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - B/op",
            "value": 736,
            "unit": "B/op",
            "extra": "877296 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "877296 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap",
            "value": 1250,
            "unit": "ns/op\t     720 B/op\t       8 allocs/op",
            "extra": "875448 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - ns/op",
            "value": 1250,
            "unit": "ns/op",
            "extra": "875448 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - B/op",
            "value": 720,
            "unit": "B/op",
            "extra": "875448 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "875448 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt",
            "value": 896.2,
            "unit": "ns/op\t    2448 B/op\t       4 allocs/op",
            "extra": "1328186 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - ns/op",
            "value": 896.2,
            "unit": "ns/op",
            "extra": "1328186 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - B/op",
            "value": 2448,
            "unit": "B/op",
            "extra": "1328186 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - allocs/op",
            "value": 4,
            "unit": "allocs/op",
            "extra": "1328186 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline",
            "value": 112532,
            "unit": "ns/op\t   13432 B/op\t     117 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - ns/op",
            "value": 112532,
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
            "value": 72223,
            "unit": "ns/op\t   15176 B/op\t     205 allocs/op",
            "extra": "16639 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - ns/op",
            "value": 72223,
            "unit": "ns/op",
            "extra": "16639 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - B/op",
            "value": 15176,
            "unit": "B/op",
            "extra": "16639 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - allocs/op",
            "value": 205,
            "unit": "allocs/op",
            "extra": "16639 times\n4 procs"
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
          "id": "6d62995f8cfde374ec1d4ebfaa7a76be0bf48e58",
          "message": "chore(deps): update github/codeql-action action to v4.38.2 (#145)\n\nCo-authored-by: renovate[bot] <29139614+renovate[bot]@users.noreply.github.com>",
          "timestamp": "2026-09-25T01:19:08Z",
          "url": "https://github.com/moov-io/signedxml/commit/6d62995f8cfde374ec1d4ebfaa7a76be0bf48e58"
        },
        "date": 1790507357965,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkEncryptElement",
            "value": 5774,
            "unit": "ns/op\t    8600 B/op\t      23 allocs/op",
            "extra": "197482 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - ns/op",
            "value": 5774,
            "unit": "ns/op",
            "extra": "197482 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - B/op",
            "value": 8600,
            "unit": "B/op",
            "extra": "197482 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - allocs/op",
            "value": 23,
            "unit": "allocs/op",
            "extra": "197482 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement",
            "value": 16556,
            "unit": "ns/op\t   10400 B/op\t      27 allocs/op",
            "extra": "72740 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - ns/op",
            "value": 16556,
            "unit": "ns/op",
            "extra": "72740 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - B/op",
            "value": 10400,
            "unit": "B/op",
            "extra": "72740 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - allocs/op",
            "value": 27,
            "unit": "allocs/op",
            "extra": "72740 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt",
            "value": 188071,
            "unit": "ns/op\t   24176 B/op\t     118 allocs/op",
            "extra": "6115 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - ns/op",
            "value": 188071,
            "unit": "ns/op",
            "extra": "6115 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - B/op",
            "value": 24176,
            "unit": "B/op",
            "extra": "6115 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - allocs/op",
            "value": 118,
            "unit": "allocs/op",
            "extra": "6115 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement",
            "value": 106145,
            "unit": "ns/op\t    1617 B/op\t      24 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - ns/op",
            "value": 106145,
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
            "value": 107049,
            "unit": "ns/op\t    3296 B/op\t      44 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - ns/op",
            "value": 107049,
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
            "value": 1240,
            "unit": "ns/op\t     736 B/op\t       8 allocs/op",
            "extra": "861836 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - ns/op",
            "value": 1240,
            "unit": "ns/op",
            "extra": "861836 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - B/op",
            "value": 736,
            "unit": "B/op",
            "extra": "861836 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "861836 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap",
            "value": 1282,
            "unit": "ns/op\t     720 B/op\t       8 allocs/op",
            "extra": "866131 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - ns/op",
            "value": 1282,
            "unit": "ns/op",
            "extra": "866131 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - B/op",
            "value": 720,
            "unit": "B/op",
            "extra": "866131 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "866131 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt",
            "value": 904.7,
            "unit": "ns/op\t    2448 B/op\t       4 allocs/op",
            "extra": "1331034 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - ns/op",
            "value": 904.7,
            "unit": "ns/op",
            "extra": "1331034 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - B/op",
            "value": 2448,
            "unit": "B/op",
            "extra": "1331034 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - allocs/op",
            "value": 4,
            "unit": "allocs/op",
            "extra": "1331034 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline",
            "value": 113741,
            "unit": "ns/op\t   13432 B/op\t     117 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - ns/op",
            "value": 113741,
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
            "value": 74309,
            "unit": "ns/op\t   15176 B/op\t     205 allocs/op",
            "extra": "16267 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - ns/op",
            "value": 74309,
            "unit": "ns/op",
            "extra": "16267 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - B/op",
            "value": 15176,
            "unit": "B/op",
            "extra": "16267 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - allocs/op",
            "value": 205,
            "unit": "allocs/op",
            "extra": "16267 times\n4 procs"
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
          "id": "6d62995f8cfde374ec1d4ebfaa7a76be0bf48e58",
          "message": "chore(deps): update github/codeql-action action to v4.38.2 (#145)\n\nCo-authored-by: renovate[bot] <29139614+renovate[bot]@users.noreply.github.com>",
          "timestamp": "2026-09-25T01:19:08Z",
          "url": "https://github.com/moov-io/signedxml/commit/6d62995f8cfde374ec1d4ebfaa7a76be0bf48e58"
        },
        "date": 1790598902364,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkEncryptElement",
            "value": 6976,
            "unit": "ns/op\t    8600 B/op\t      23 allocs/op",
            "extra": "163088 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - ns/op",
            "value": 6976,
            "unit": "ns/op",
            "extra": "163088 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - B/op",
            "value": 8600,
            "unit": "B/op",
            "extra": "163088 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - allocs/op",
            "value": 23,
            "unit": "allocs/op",
            "extra": "163088 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement",
            "value": 16586,
            "unit": "ns/op\t   10400 B/op\t      27 allocs/op",
            "extra": "71212 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - ns/op",
            "value": 16586,
            "unit": "ns/op",
            "extra": "71212 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - B/op",
            "value": 10400,
            "unit": "B/op",
            "extra": "71212 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - allocs/op",
            "value": 27,
            "unit": "allocs/op",
            "extra": "71212 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt",
            "value": 186234,
            "unit": "ns/op\t   24176 B/op\t     118 allocs/op",
            "extra": "6180 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - ns/op",
            "value": 186234,
            "unit": "ns/op",
            "extra": "6180 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - B/op",
            "value": 24176,
            "unit": "B/op",
            "extra": "6180 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - allocs/op",
            "value": 118,
            "unit": "allocs/op",
            "extra": "6180 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement",
            "value": 105323,
            "unit": "ns/op\t    1617 B/op\t      24 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - ns/op",
            "value": 105323,
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
            "value": 107723,
            "unit": "ns/op\t    3296 B/op\t      44 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - ns/op",
            "value": 107723,
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
            "value": 1230,
            "unit": "ns/op\t     736 B/op\t       8 allocs/op",
            "extra": "860223 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - ns/op",
            "value": 1230,
            "unit": "ns/op",
            "extra": "860223 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - B/op",
            "value": 736,
            "unit": "B/op",
            "extra": "860223 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "860223 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap",
            "value": 1258,
            "unit": "ns/op\t     720 B/op\t       8 allocs/op",
            "extra": "863736 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - ns/op",
            "value": 1258,
            "unit": "ns/op",
            "extra": "863736 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - B/op",
            "value": 720,
            "unit": "B/op",
            "extra": "863736 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "863736 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt",
            "value": 982,
            "unit": "ns/op\t    2448 B/op\t       4 allocs/op",
            "extra": "1309378 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - ns/op",
            "value": 982,
            "unit": "ns/op",
            "extra": "1309378 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - B/op",
            "value": 2448,
            "unit": "B/op",
            "extra": "1309378 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - allocs/op",
            "value": 4,
            "unit": "allocs/op",
            "extra": "1309378 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline",
            "value": 113432,
            "unit": "ns/op\t   13432 B/op\t     117 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - ns/op",
            "value": 113432,
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
            "value": 73709,
            "unit": "ns/op\t   15176 B/op\t     205 allocs/op",
            "extra": "16159 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - ns/op",
            "value": 73709,
            "unit": "ns/op",
            "extra": "16159 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - B/op",
            "value": 15176,
            "unit": "B/op",
            "extra": "16159 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - allocs/op",
            "value": 205,
            "unit": "allocs/op",
            "extra": "16159 times\n4 procs"
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
          "id": "6d62995f8cfde374ec1d4ebfaa7a76be0bf48e58",
          "message": "chore(deps): update github/codeql-action action to v4.38.2 (#145)\n\nCo-authored-by: renovate[bot] <29139614+renovate[bot]@users.noreply.github.com>",
          "timestamp": "2026-09-25T01:19:08Z",
          "url": "https://github.com/moov-io/signedxml/commit/6d62995f8cfde374ec1d4ebfaa7a76be0bf48e58"
        },
        "date": 1790682944502,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkEncryptElement",
            "value": 6054,
            "unit": "ns/op\t    8600 B/op\t      23 allocs/op",
            "extra": "182676 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - ns/op",
            "value": 6054,
            "unit": "ns/op",
            "extra": "182676 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - B/op",
            "value": 8600,
            "unit": "B/op",
            "extra": "182676 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - allocs/op",
            "value": 23,
            "unit": "allocs/op",
            "extra": "182676 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement",
            "value": 16389,
            "unit": "ns/op\t   10400 B/op\t      27 allocs/op",
            "extra": "72386 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - ns/op",
            "value": 16389,
            "unit": "ns/op",
            "extra": "72386 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - B/op",
            "value": 10400,
            "unit": "B/op",
            "extra": "72386 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - allocs/op",
            "value": 27,
            "unit": "allocs/op",
            "extra": "72386 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt",
            "value": 202648,
            "unit": "ns/op\t   24176 B/op\t     118 allocs/op",
            "extra": "5632 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - ns/op",
            "value": 202648,
            "unit": "ns/op",
            "extra": "5632 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - B/op",
            "value": 24176,
            "unit": "B/op",
            "extra": "5632 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - allocs/op",
            "value": 118,
            "unit": "allocs/op",
            "extra": "5632 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement",
            "value": 116299,
            "unit": "ns/op\t    1617 B/op\t      24 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - ns/op",
            "value": 116299,
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
            "value": 118228,
            "unit": "ns/op\t    3296 B/op\t      44 allocs/op",
            "extra": "9853 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - ns/op",
            "value": 118228,
            "unit": "ns/op",
            "extra": "9853 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - B/op",
            "value": 3296,
            "unit": "B/op",
            "extra": "9853 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - allocs/op",
            "value": 44,
            "unit": "allocs/op",
            "extra": "9853 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap",
            "value": 1253,
            "unit": "ns/op\t     736 B/op\t       8 allocs/op",
            "extra": "859953 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - ns/op",
            "value": 1253,
            "unit": "ns/op",
            "extra": "859953 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - B/op",
            "value": 736,
            "unit": "B/op",
            "extra": "859953 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "859953 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap",
            "value": 1267,
            "unit": "ns/op\t     720 B/op\t       8 allocs/op",
            "extra": "830944 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - ns/op",
            "value": 1267,
            "unit": "ns/op",
            "extra": "830944 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - B/op",
            "value": 720,
            "unit": "B/op",
            "extra": "830944 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "830944 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt",
            "value": 956.5,
            "unit": "ns/op\t    2448 B/op\t       4 allocs/op",
            "extra": "1319589 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - ns/op",
            "value": 956.5,
            "unit": "ns/op",
            "extra": "1319589 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - B/op",
            "value": 2448,
            "unit": "B/op",
            "extra": "1319589 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - allocs/op",
            "value": 4,
            "unit": "allocs/op",
            "extra": "1319589 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline",
            "value": 124966,
            "unit": "ns/op\t   13432 B/op\t     117 allocs/op",
            "extra": "9302 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - ns/op",
            "value": 124966,
            "unit": "ns/op",
            "extra": "9302 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - B/op",
            "value": 13432,
            "unit": "B/op",
            "extra": "9302 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - allocs/op",
            "value": 117,
            "unit": "allocs/op",
            "extra": "9302 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline",
            "value": 77282,
            "unit": "ns/op\t   15176 B/op\t     205 allocs/op",
            "extra": "15435 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - ns/op",
            "value": 77282,
            "unit": "ns/op",
            "extra": "15435 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - B/op",
            "value": 15176,
            "unit": "B/op",
            "extra": "15435 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - allocs/op",
            "value": 205,
            "unit": "allocs/op",
            "extra": "15435 times\n4 procs"
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
          "id": "6d62995f8cfde374ec1d4ebfaa7a76be0bf48e58",
          "message": "chore(deps): update github/codeql-action action to v4.38.2 (#145)\n\nCo-authored-by: renovate[bot] <29139614+renovate[bot]@users.noreply.github.com>",
          "timestamp": "2026-09-25T01:19:08Z",
          "url": "https://github.com/moov-io/signedxml/commit/6d62995f8cfde374ec1d4ebfaa7a76be0bf48e58"
        },
        "date": 1790768620832,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkEncryptElement",
            "value": 5562,
            "unit": "ns/op\t    8600 B/op\t      23 allocs/op",
            "extra": "207841 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - ns/op",
            "value": 5562,
            "unit": "ns/op",
            "extra": "207841 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - B/op",
            "value": 8600,
            "unit": "B/op",
            "extra": "207841 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - allocs/op",
            "value": 23,
            "unit": "allocs/op",
            "extra": "207841 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement",
            "value": 14010,
            "unit": "ns/op\t   10400 B/op\t      27 allocs/op",
            "extra": "85395 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - ns/op",
            "value": 14010,
            "unit": "ns/op",
            "extra": "85395 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - B/op",
            "value": 10400,
            "unit": "B/op",
            "extra": "85395 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - allocs/op",
            "value": 27,
            "unit": "allocs/op",
            "extra": "85395 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt",
            "value": 179997,
            "unit": "ns/op\t   24176 B/op\t     118 allocs/op",
            "extra": "6433 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - ns/op",
            "value": 179997,
            "unit": "ns/op",
            "extra": "6433 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - B/op",
            "value": 24176,
            "unit": "B/op",
            "extra": "6433 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - allocs/op",
            "value": 118,
            "unit": "allocs/op",
            "extra": "6433 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement",
            "value": 103702,
            "unit": "ns/op\t    1617 B/op\t      24 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - ns/op",
            "value": 103702,
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
            "value": 104942,
            "unit": "ns/op\t    3296 B/op\t      44 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - ns/op",
            "value": 104942,
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
            "value": 1044,
            "unit": "ns/op\t     736 B/op\t       8 allocs/op",
            "extra": "1000000 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - ns/op",
            "value": 1044,
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
            "value": 1084,
            "unit": "ns/op\t     720 B/op\t       8 allocs/op",
            "extra": "1000000 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - ns/op",
            "value": 1084,
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
            "value": 930.2,
            "unit": "ns/op\t    2448 B/op\t       4 allocs/op",
            "extra": "1297486 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - ns/op",
            "value": 930.2,
            "unit": "ns/op",
            "extra": "1297486 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - B/op",
            "value": 2448,
            "unit": "B/op",
            "extra": "1297486 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - allocs/op",
            "value": 4,
            "unit": "allocs/op",
            "extra": "1297486 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline",
            "value": 111331,
            "unit": "ns/op\t   13432 B/op\t     117 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - ns/op",
            "value": 111331,
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
            "value": 70542,
            "unit": "ns/op\t   15176 B/op\t     205 allocs/op",
            "extra": "16791 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - ns/op",
            "value": 70542,
            "unit": "ns/op",
            "extra": "16791 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - B/op",
            "value": 15176,
            "unit": "B/op",
            "extra": "16791 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - allocs/op",
            "value": 205,
            "unit": "allocs/op",
            "extra": "16791 times\n4 procs"
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
          "id": "6d62995f8cfde374ec1d4ebfaa7a76be0bf48e58",
          "message": "chore(deps): update github/codeql-action action to v4.38.2 (#145)\n\nCo-authored-by: renovate[bot] <29139614+renovate[bot]@users.noreply.github.com>",
          "timestamp": "2026-09-25T01:19:08Z",
          "url": "https://github.com/moov-io/signedxml/commit/6d62995f8cfde374ec1d4ebfaa7a76be0bf48e58"
        },
        "date": 1790856741394,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkEncryptElement",
            "value": 5739,
            "unit": "ns/op\t    8600 B/op\t      23 allocs/op",
            "extra": "214260 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - ns/op",
            "value": 5739,
            "unit": "ns/op",
            "extra": "214260 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - B/op",
            "value": 8600,
            "unit": "B/op",
            "extra": "214260 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - allocs/op",
            "value": 23,
            "unit": "allocs/op",
            "extra": "214260 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement",
            "value": 16725,
            "unit": "ns/op\t   10400 B/op\t      27 allocs/op",
            "extra": "71300 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - ns/op",
            "value": 16725,
            "unit": "ns/op",
            "extra": "71300 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - B/op",
            "value": 10400,
            "unit": "B/op",
            "extra": "71300 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - allocs/op",
            "value": 27,
            "unit": "allocs/op",
            "extra": "71300 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt",
            "value": 185338,
            "unit": "ns/op\t   24176 B/op\t     118 allocs/op",
            "extra": "6405 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - ns/op",
            "value": 185338,
            "unit": "ns/op",
            "extra": "6405 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - B/op",
            "value": 24176,
            "unit": "B/op",
            "extra": "6405 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - allocs/op",
            "value": 118,
            "unit": "allocs/op",
            "extra": "6405 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement",
            "value": 105411,
            "unit": "ns/op\t    1617 B/op\t      24 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - ns/op",
            "value": 105411,
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
            "value": 106845,
            "unit": "ns/op\t    3296 B/op\t      44 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - ns/op",
            "value": 106845,
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
            "extra": "975886 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - ns/op",
            "value": 1232,
            "unit": "ns/op",
            "extra": "975886 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - B/op",
            "value": 736,
            "unit": "B/op",
            "extra": "975886 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "975886 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap",
            "value": 1259,
            "unit": "ns/op\t     720 B/op\t       8 allocs/op",
            "extra": "871572 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - ns/op",
            "value": 1259,
            "unit": "ns/op",
            "extra": "871572 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - B/op",
            "value": 720,
            "unit": "B/op",
            "extra": "871572 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "871572 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt",
            "value": 913.4,
            "unit": "ns/op\t    2448 B/op\t       4 allocs/op",
            "extra": "1248330 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - ns/op",
            "value": 913.4,
            "unit": "ns/op",
            "extra": "1248330 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - B/op",
            "value": 2448,
            "unit": "B/op",
            "extra": "1248330 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - allocs/op",
            "value": 4,
            "unit": "allocs/op",
            "extra": "1248330 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline",
            "value": 113534,
            "unit": "ns/op\t   13432 B/op\t     117 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - ns/op",
            "value": 113534,
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
            "value": 73819,
            "unit": "ns/op\t   15176 B/op\t     205 allocs/op",
            "extra": "16257 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - ns/op",
            "value": 73819,
            "unit": "ns/op",
            "extra": "16257 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - B/op",
            "value": 15176,
            "unit": "B/op",
            "extra": "16257 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - allocs/op",
            "value": 205,
            "unit": "allocs/op",
            "extra": "16257 times\n4 procs"
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
          "id": "ba54914d8f2d9c31290d992e821370cf2570e0aa",
          "message": "fix(deps): update module github.com/sirosfoundation/go-cryptoutil to v0.7.1 (#146)\n\nCo-authored-by: renovate[bot] <29139614+renovate[bot]@users.noreply.github.com>",
          "timestamp": "2026-10-01T15:03:15Z",
          "url": "https://github.com/moov-io/signedxml/commit/ba54914d8f2d9c31290d992e821370cf2570e0aa"
        },
        "date": 1790941327280,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkEncryptElement",
            "value": 5548,
            "unit": "ns/op\t    8600 B/op\t      23 allocs/op",
            "extra": "209210 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - ns/op",
            "value": 5548,
            "unit": "ns/op",
            "extra": "209210 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - B/op",
            "value": 8600,
            "unit": "B/op",
            "extra": "209210 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - allocs/op",
            "value": 23,
            "unit": "allocs/op",
            "extra": "209210 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement",
            "value": 16216,
            "unit": "ns/op\t   10400 B/op\t      27 allocs/op",
            "extra": "73111 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - ns/op",
            "value": 16216,
            "unit": "ns/op",
            "extra": "73111 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - B/op",
            "value": 10400,
            "unit": "B/op",
            "extra": "73111 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - allocs/op",
            "value": 27,
            "unit": "allocs/op",
            "extra": "73111 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt",
            "value": 182766,
            "unit": "ns/op\t   24176 B/op\t     118 allocs/op",
            "extra": "6211 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - ns/op",
            "value": 182766,
            "unit": "ns/op",
            "extra": "6211 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - B/op",
            "value": 24176,
            "unit": "B/op",
            "extra": "6211 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - allocs/op",
            "value": 118,
            "unit": "allocs/op",
            "extra": "6211 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement",
            "value": 105245,
            "unit": "ns/op\t    1617 B/op\t      24 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - ns/op",
            "value": 105245,
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
            "value": 107381,
            "unit": "ns/op\t    3296 B/op\t      44 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - ns/op",
            "value": 107381,
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
            "extra": "871616 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - ns/op",
            "value": 1228,
            "unit": "ns/op",
            "extra": "871616 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - B/op",
            "value": 736,
            "unit": "B/op",
            "extra": "871616 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "871616 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap",
            "value": 1237,
            "unit": "ns/op\t     720 B/op\t       8 allocs/op",
            "extra": "889105 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - ns/op",
            "value": 1237,
            "unit": "ns/op",
            "extra": "889105 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - B/op",
            "value": 720,
            "unit": "B/op",
            "extra": "889105 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "889105 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt",
            "value": 917.3,
            "unit": "ns/op\t    2448 B/op\t       4 allocs/op",
            "extra": "1284166 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - ns/op",
            "value": 917.3,
            "unit": "ns/op",
            "extra": "1284166 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - B/op",
            "value": 2448,
            "unit": "B/op",
            "extra": "1284166 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - allocs/op",
            "value": 4,
            "unit": "allocs/op",
            "extra": "1284166 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline",
            "value": 113090,
            "unit": "ns/op\t   13432 B/op\t     117 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - ns/op",
            "value": 113090,
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
            "value": 72563,
            "unit": "ns/op\t   15176 B/op\t     205 allocs/op",
            "extra": "16576 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - ns/op",
            "value": 72563,
            "unit": "ns/op",
            "extra": "16576 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - B/op",
            "value": 15176,
            "unit": "B/op",
            "extra": "16576 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - allocs/op",
            "value": 205,
            "unit": "allocs/op",
            "extra": "16576 times\n4 procs"
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
          "id": "ba54914d8f2d9c31290d992e821370cf2570e0aa",
          "message": "fix(deps): update module github.com/sirosfoundation/go-cryptoutil to v0.7.1 (#146)\n\nCo-authored-by: renovate[bot] <29139614+renovate[bot]@users.noreply.github.com>",
          "timestamp": "2026-10-01T15:03:15Z",
          "url": "https://github.com/moov-io/signedxml/commit/ba54914d8f2d9c31290d992e821370cf2570e0aa"
        },
        "date": 1791024944156,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkEncryptElement",
            "value": 5846,
            "unit": "ns/op\t    8600 B/op\t      23 allocs/op",
            "extra": "204031 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - ns/op",
            "value": 5846,
            "unit": "ns/op",
            "extra": "204031 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - B/op",
            "value": 8600,
            "unit": "B/op",
            "extra": "204031 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - allocs/op",
            "value": 23,
            "unit": "allocs/op",
            "extra": "204031 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement",
            "value": 15657,
            "unit": "ns/op\t   10400 B/op\t      27 allocs/op",
            "extra": "76263 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - ns/op",
            "value": 15657,
            "unit": "ns/op",
            "extra": "76263 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - B/op",
            "value": 10400,
            "unit": "B/op",
            "extra": "76263 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - allocs/op",
            "value": 27,
            "unit": "allocs/op",
            "extra": "76263 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt",
            "value": 165004,
            "unit": "ns/op\t   24176 B/op\t     118 allocs/op",
            "extra": "6900 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - ns/op",
            "value": 165004,
            "unit": "ns/op",
            "extra": "6900 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - B/op",
            "value": 24176,
            "unit": "B/op",
            "extra": "6900 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - allocs/op",
            "value": 118,
            "unit": "allocs/op",
            "extra": "6900 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement",
            "value": 92292,
            "unit": "ns/op\t    1617 B/op\t      24 allocs/op",
            "extra": "12999 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - ns/op",
            "value": 92292,
            "unit": "ns/op",
            "extra": "12999 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - B/op",
            "value": 1617,
            "unit": "B/op",
            "extra": "12999 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - allocs/op",
            "value": 24,
            "unit": "allocs/op",
            "extra": "12999 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey",
            "value": 93714,
            "unit": "ns/op\t    3296 B/op\t      44 allocs/op",
            "extra": "12818 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - ns/op",
            "value": 93714,
            "unit": "ns/op",
            "extra": "12818 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - B/op",
            "value": 3296,
            "unit": "B/op",
            "extra": "12818 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - allocs/op",
            "value": 44,
            "unit": "allocs/op",
            "extra": "12818 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap",
            "value": 1105,
            "unit": "ns/op\t     736 B/op\t       8 allocs/op",
            "extra": "970056 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - ns/op",
            "value": 1105,
            "unit": "ns/op",
            "extra": "970056 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - B/op",
            "value": 736,
            "unit": "B/op",
            "extra": "970056 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "970056 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap",
            "value": 1125,
            "unit": "ns/op\t     720 B/op\t       8 allocs/op",
            "extra": "986876 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - ns/op",
            "value": 1125,
            "unit": "ns/op",
            "extra": "986876 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - B/op",
            "value": 720,
            "unit": "B/op",
            "extra": "986876 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "986876 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt",
            "value": 929.2,
            "unit": "ns/op\t    2448 B/op\t       4 allocs/op",
            "extra": "1287612 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - ns/op",
            "value": 929.2,
            "unit": "ns/op",
            "extra": "1287612 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - B/op",
            "value": 2448,
            "unit": "B/op",
            "extra": "1287612 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - allocs/op",
            "value": 4,
            "unit": "allocs/op",
            "extra": "1287612 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline",
            "value": 99879,
            "unit": "ns/op\t   13432 B/op\t     117 allocs/op",
            "extra": "12024 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - ns/op",
            "value": 99879,
            "unit": "ns/op",
            "extra": "12024 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - B/op",
            "value": 13432,
            "unit": "B/op",
            "extra": "12024 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - allocs/op",
            "value": 117,
            "unit": "allocs/op",
            "extra": "12024 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline",
            "value": 65607,
            "unit": "ns/op\t   15176 B/op\t     205 allocs/op",
            "extra": "18202 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - ns/op",
            "value": 65607,
            "unit": "ns/op",
            "extra": "18202 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - B/op",
            "value": 15176,
            "unit": "B/op",
            "extra": "18202 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - allocs/op",
            "value": 205,
            "unit": "allocs/op",
            "extra": "18202 times\n4 procs"
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
          "id": "ba54914d8f2d9c31290d992e821370cf2570e0aa",
          "message": "fix(deps): update module github.com/sirosfoundation/go-cryptoutil to v0.7.1 (#146)\n\nCo-authored-by: renovate[bot] <29139614+renovate[bot]@users.noreply.github.com>",
          "timestamp": "2026-10-01T15:03:15Z",
          "url": "https://github.com/moov-io/signedxml/commit/ba54914d8f2d9c31290d992e821370cf2570e0aa"
        },
        "date": 1791113866510,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkEncryptElement",
            "value": 5785,
            "unit": "ns/op\t    8600 B/op\t      23 allocs/op",
            "extra": "177214 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - ns/op",
            "value": 5785,
            "unit": "ns/op",
            "extra": "177214 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - B/op",
            "value": 8600,
            "unit": "B/op",
            "extra": "177214 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - allocs/op",
            "value": 23,
            "unit": "allocs/op",
            "extra": "177214 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement",
            "value": 14022,
            "unit": "ns/op\t   10400 B/op\t      27 allocs/op",
            "extra": "83784 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - ns/op",
            "value": 14022,
            "unit": "ns/op",
            "extra": "83784 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - B/op",
            "value": 10400,
            "unit": "B/op",
            "extra": "83784 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - allocs/op",
            "value": 27,
            "unit": "allocs/op",
            "extra": "83784 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt",
            "value": 183448,
            "unit": "ns/op\t   24176 B/op\t     118 allocs/op",
            "extra": "6440 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - ns/op",
            "value": 183448,
            "unit": "ns/op",
            "extra": "6440 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - B/op",
            "value": 24176,
            "unit": "B/op",
            "extra": "6440 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - allocs/op",
            "value": 118,
            "unit": "allocs/op",
            "extra": "6440 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement",
            "value": 107732,
            "unit": "ns/op\t    1617 B/op\t      24 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - ns/op",
            "value": 107732,
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
            "value": 105867,
            "unit": "ns/op\t    3296 B/op\t      44 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - ns/op",
            "value": 105867,
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
            "value": 1061,
            "unit": "ns/op\t     736 B/op\t       8 allocs/op",
            "extra": "1134790 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - ns/op",
            "value": 1061,
            "unit": "ns/op",
            "extra": "1134790 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - B/op",
            "value": 736,
            "unit": "B/op",
            "extra": "1134790 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "1134790 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap",
            "value": 1090,
            "unit": "ns/op\t     720 B/op\t       8 allocs/op",
            "extra": "1000000 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - ns/op",
            "value": 1090,
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
            "value": 948,
            "unit": "ns/op\t    2448 B/op\t       4 allocs/op",
            "extra": "1262916 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - ns/op",
            "value": 948,
            "unit": "ns/op",
            "extra": "1262916 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - B/op",
            "value": 2448,
            "unit": "B/op",
            "extra": "1262916 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - allocs/op",
            "value": 4,
            "unit": "allocs/op",
            "extra": "1262916 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline",
            "value": 111699,
            "unit": "ns/op\t   13432 B/op\t     117 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - ns/op",
            "value": 111699,
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
            "value": 71694,
            "unit": "ns/op\t   15176 B/op\t     205 allocs/op",
            "extra": "16704 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - ns/op",
            "value": 71694,
            "unit": "ns/op",
            "extra": "16704 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - B/op",
            "value": 15176,
            "unit": "B/op",
            "extra": "16704 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - allocs/op",
            "value": 205,
            "unit": "allocs/op",
            "extra": "16704 times\n4 procs"
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
          "id": "ba54914d8f2d9c31290d992e821370cf2570e0aa",
          "message": "fix(deps): update module github.com/sirosfoundation/go-cryptoutil to v0.7.1 (#146)\n\nCo-authored-by: renovate[bot] <29139614+renovate[bot]@users.noreply.github.com>",
          "timestamp": "2026-10-01T15:03:15Z",
          "url": "https://github.com/moov-io/signedxml/commit/ba54914d8f2d9c31290d992e821370cf2570e0aa"
        },
        "date": 1791206118100,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkEncryptElement",
            "value": 3198,
            "unit": "ns/op\t    8600 B/op\t      23 allocs/op",
            "extra": "373975 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - ns/op",
            "value": 3198,
            "unit": "ns/op",
            "extra": "373975 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - B/op",
            "value": 8600,
            "unit": "B/op",
            "extra": "373975 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - allocs/op",
            "value": 23,
            "unit": "allocs/op",
            "extra": "373975 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement",
            "value": 8654,
            "unit": "ns/op\t   10400 B/op\t      27 allocs/op",
            "extra": "136953 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - ns/op",
            "value": 8654,
            "unit": "ns/op",
            "extra": "136953 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - B/op",
            "value": 10400,
            "unit": "B/op",
            "extra": "136953 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - allocs/op",
            "value": 27,
            "unit": "allocs/op",
            "extra": "136953 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt",
            "value": 104624,
            "unit": "ns/op\t   24176 B/op\t     118 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - ns/op",
            "value": 104624,
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
            "value": 60086,
            "unit": "ns/op\t    1617 B/op\t      24 allocs/op",
            "extra": "19725 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - ns/op",
            "value": 60086,
            "unit": "ns/op",
            "extra": "19725 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - B/op",
            "value": 1617,
            "unit": "B/op",
            "extra": "19725 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - allocs/op",
            "value": 24,
            "unit": "allocs/op",
            "extra": "19725 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey",
            "value": 59626,
            "unit": "ns/op\t    3296 B/op\t      44 allocs/op",
            "extra": "19743 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - ns/op",
            "value": 59626,
            "unit": "ns/op",
            "extra": "19743 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - B/op",
            "value": 3296,
            "unit": "B/op",
            "extra": "19743 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - allocs/op",
            "value": 44,
            "unit": "allocs/op",
            "extra": "19743 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap",
            "value": 746.1,
            "unit": "ns/op\t     736 B/op\t       8 allocs/op",
            "extra": "1634919 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - ns/op",
            "value": 746.1,
            "unit": "ns/op",
            "extra": "1634919 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - B/op",
            "value": 736,
            "unit": "B/op",
            "extra": "1634919 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "1634919 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap",
            "value": 767.7,
            "unit": "ns/op\t     720 B/op\t       8 allocs/op",
            "extra": "1584856 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - ns/op",
            "value": 767.7,
            "unit": "ns/op",
            "extra": "1584856 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - B/op",
            "value": 720,
            "unit": "B/op",
            "extra": "1584856 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "1584856 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt",
            "value": 573.4,
            "unit": "ns/op\t    2448 B/op\t       4 allocs/op",
            "extra": "2109854 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - ns/op",
            "value": 573.4,
            "unit": "ns/op",
            "extra": "2109854 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - B/op",
            "value": 2448,
            "unit": "B/op",
            "extra": "2109854 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - allocs/op",
            "value": 4,
            "unit": "allocs/op",
            "extra": "2109854 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline",
            "value": 64093,
            "unit": "ns/op\t   13432 B/op\t     117 allocs/op",
            "extra": "18604 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - ns/op",
            "value": 64093,
            "unit": "ns/op",
            "extra": "18604 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - B/op",
            "value": 13432,
            "unit": "B/op",
            "extra": "18604 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - allocs/op",
            "value": 117,
            "unit": "allocs/op",
            "extra": "18604 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline",
            "value": 40460,
            "unit": "ns/op\t   15176 B/op\t     205 allocs/op",
            "extra": "29808 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - ns/op",
            "value": 40460,
            "unit": "ns/op",
            "extra": "29808 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - B/op",
            "value": 15176,
            "unit": "B/op",
            "extra": "29808 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - allocs/op",
            "value": 205,
            "unit": "allocs/op",
            "extra": "29808 times\n4 procs"
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
          "id": "ba54914d8f2d9c31290d992e821370cf2570e0aa",
          "message": "fix(deps): update module github.com/sirosfoundation/go-cryptoutil to v0.7.1 (#146)\n\nCo-authored-by: renovate[bot] <29139614+renovate[bot]@users.noreply.github.com>",
          "timestamp": "2026-10-01T15:03:15Z",
          "url": "https://github.com/moov-io/signedxml/commit/ba54914d8f2d9c31290d992e821370cf2570e0aa"
        },
        "date": 1791290016839,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkEncryptElement",
            "value": 5618,
            "unit": "ns/op\t    8600 B/op\t      23 allocs/op",
            "extra": "213265 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - ns/op",
            "value": 5618,
            "unit": "ns/op",
            "extra": "213265 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - B/op",
            "value": 8600,
            "unit": "B/op",
            "extra": "213265 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - allocs/op",
            "value": 23,
            "unit": "allocs/op",
            "extra": "213265 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement",
            "value": 14791,
            "unit": "ns/op\t   10400 B/op\t      27 allocs/op",
            "extra": "82662 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - ns/op",
            "value": 14791,
            "unit": "ns/op",
            "extra": "82662 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - B/op",
            "value": 10400,
            "unit": "B/op",
            "extra": "82662 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - allocs/op",
            "value": 27,
            "unit": "allocs/op",
            "extra": "82662 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt",
            "value": 151045,
            "unit": "ns/op\t   24176 B/op\t     118 allocs/op",
            "extra": "7741 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - ns/op",
            "value": 151045,
            "unit": "ns/op",
            "extra": "7741 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - B/op",
            "value": 24176,
            "unit": "B/op",
            "extra": "7741 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - allocs/op",
            "value": 118,
            "unit": "allocs/op",
            "extra": "7741 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement",
            "value": 83408,
            "unit": "ns/op\t    1617 B/op\t      24 allocs/op",
            "extra": "14360 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - ns/op",
            "value": 83408,
            "unit": "ns/op",
            "extra": "14360 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - B/op",
            "value": 1617,
            "unit": "B/op",
            "extra": "14360 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - allocs/op",
            "value": 24,
            "unit": "allocs/op",
            "extra": "14360 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey",
            "value": 84064,
            "unit": "ns/op\t    3296 B/op\t      44 allocs/op",
            "extra": "13969 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - ns/op",
            "value": 84064,
            "unit": "ns/op",
            "extra": "13969 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - B/op",
            "value": 3296,
            "unit": "B/op",
            "extra": "13969 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - allocs/op",
            "value": 44,
            "unit": "allocs/op",
            "extra": "13969 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap",
            "value": 1032,
            "unit": "ns/op\t     736 B/op\t       8 allocs/op",
            "extra": "1000000 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - ns/op",
            "value": 1032,
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
            "value": 1027,
            "unit": "ns/op\t     720 B/op\t       8 allocs/op",
            "extra": "1000000 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - ns/op",
            "value": 1027,
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
            "value": 862.2,
            "unit": "ns/op\t    2448 B/op\t       4 allocs/op",
            "extra": "1335403 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - ns/op",
            "value": 862.2,
            "unit": "ns/op",
            "extra": "1335403 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - B/op",
            "value": 2448,
            "unit": "B/op",
            "extra": "1335403 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - allocs/op",
            "value": 4,
            "unit": "allocs/op",
            "extra": "1335403 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline",
            "value": 92154,
            "unit": "ns/op\t   13432 B/op\t     117 allocs/op",
            "extra": "13017 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - ns/op",
            "value": 92154,
            "unit": "ns/op",
            "extra": "13017 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - B/op",
            "value": 13432,
            "unit": "B/op",
            "extra": "13017 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - allocs/op",
            "value": 117,
            "unit": "allocs/op",
            "extra": "13017 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline",
            "value": 60645,
            "unit": "ns/op\t   15176 B/op\t     205 allocs/op",
            "extra": "19528 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - ns/op",
            "value": 60645,
            "unit": "ns/op",
            "extra": "19528 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - B/op",
            "value": 15176,
            "unit": "B/op",
            "extra": "19528 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - allocs/op",
            "value": 205,
            "unit": "allocs/op",
            "extra": "19528 times\n4 procs"
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
          "id": "4375792cde72b682eff57b1ca1018f46a59b9db8",
          "message": "fix(deps): update module github.com/sirosfoundation/go-cryptoutil to v0.7.2 (#147)\n\nCo-authored-by: renovate[bot] <29139614+renovate[bot]@users.noreply.github.com>",
          "timestamp": "2026-10-07T00:49:31Z",
          "url": "https://github.com/moov-io/signedxml/commit/4375792cde72b682eff57b1ca1018f46a59b9db8"
        },
        "date": 1791376008325,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkEncryptElement",
            "value": 5345,
            "unit": "ns/op\t    8600 B/op\t      23 allocs/op",
            "extra": "225486 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - ns/op",
            "value": 5345,
            "unit": "ns/op",
            "extra": "225486 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - B/op",
            "value": 8600,
            "unit": "B/op",
            "extra": "225486 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - allocs/op",
            "value": 23,
            "unit": "allocs/op",
            "extra": "225486 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement",
            "value": 14028,
            "unit": "ns/op\t   10400 B/op\t      27 allocs/op",
            "extra": "85393 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - ns/op",
            "value": 14028,
            "unit": "ns/op",
            "extra": "85393 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - B/op",
            "value": 10400,
            "unit": "B/op",
            "extra": "85393 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - allocs/op",
            "value": 27,
            "unit": "allocs/op",
            "extra": "85393 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt",
            "value": 148541,
            "unit": "ns/op\t   24176 B/op\t     118 allocs/op",
            "extra": "8245 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - ns/op",
            "value": 148541,
            "unit": "ns/op",
            "extra": "8245 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - B/op",
            "value": 24176,
            "unit": "B/op",
            "extra": "8245 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - allocs/op",
            "value": 118,
            "unit": "allocs/op",
            "extra": "8245 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement",
            "value": 82780,
            "unit": "ns/op\t    1617 B/op\t      24 allocs/op",
            "extra": "14460 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - ns/op",
            "value": 82780,
            "unit": "ns/op",
            "extra": "14460 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - B/op",
            "value": 1617,
            "unit": "B/op",
            "extra": "14460 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - allocs/op",
            "value": 24,
            "unit": "allocs/op",
            "extra": "14460 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey",
            "value": 82379,
            "unit": "ns/op\t    3296 B/op\t      44 allocs/op",
            "extra": "13946 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - ns/op",
            "value": 82379,
            "unit": "ns/op",
            "extra": "13946 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - B/op",
            "value": 3296,
            "unit": "B/op",
            "extra": "13946 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - allocs/op",
            "value": 44,
            "unit": "allocs/op",
            "extra": "13946 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap",
            "value": 985,
            "unit": "ns/op\t     736 B/op\t       8 allocs/op",
            "extra": "1227766 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - ns/op",
            "value": 985,
            "unit": "ns/op",
            "extra": "1227766 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - B/op",
            "value": 736,
            "unit": "B/op",
            "extra": "1227766 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "1227766 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap",
            "value": 1007,
            "unit": "ns/op\t     720 B/op\t       8 allocs/op",
            "extra": "1203319 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - ns/op",
            "value": 1007,
            "unit": "ns/op",
            "extra": "1203319 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - B/op",
            "value": 720,
            "unit": "B/op",
            "extra": "1203319 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "1203319 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt",
            "value": 844.3,
            "unit": "ns/op\t    2448 B/op\t       4 allocs/op",
            "extra": "1404752 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - ns/op",
            "value": 844.3,
            "unit": "ns/op",
            "extra": "1404752 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - B/op",
            "value": 2448,
            "unit": "B/op",
            "extra": "1404752 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - allocs/op",
            "value": 4,
            "unit": "allocs/op",
            "extra": "1404752 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline",
            "value": 90821,
            "unit": "ns/op\t   13432 B/op\t     117 allocs/op",
            "extra": "13494 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - ns/op",
            "value": 90821,
            "unit": "ns/op",
            "extra": "13494 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - B/op",
            "value": 13432,
            "unit": "B/op",
            "extra": "13494 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - allocs/op",
            "value": 117,
            "unit": "allocs/op",
            "extra": "13494 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline",
            "value": 58051,
            "unit": "ns/op\t   15176 B/op\t     205 allocs/op",
            "extra": "20347 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - ns/op",
            "value": 58051,
            "unit": "ns/op",
            "extra": "20347 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - B/op",
            "value": 15176,
            "unit": "B/op",
            "extra": "20347 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - allocs/op",
            "value": 205,
            "unit": "allocs/op",
            "extra": "20347 times\n4 procs"
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
          "id": "4375792cde72b682eff57b1ca1018f46a59b9db8",
          "message": "fix(deps): update module github.com/sirosfoundation/go-cryptoutil to v0.7.2 (#147)\n\nCo-authored-by: renovate[bot] <29139614+renovate[bot]@users.noreply.github.com>",
          "timestamp": "2026-10-07T00:49:31Z",
          "url": "https://github.com/moov-io/signedxml/commit/4375792cde72b682eff57b1ca1018f46a59b9db8"
        },
        "date": 1791462978115,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkEncryptElement",
            "value": 4720,
            "unit": "ns/op\t    8600 B/op\t      23 allocs/op",
            "extra": "242106 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - ns/op",
            "value": 4720,
            "unit": "ns/op",
            "extra": "242106 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - B/op",
            "value": 8600,
            "unit": "B/op",
            "extra": "242106 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - allocs/op",
            "value": 23,
            "unit": "allocs/op",
            "extra": "242106 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement",
            "value": 13279,
            "unit": "ns/op\t   10400 B/op\t      27 allocs/op",
            "extra": "91128 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - ns/op",
            "value": 13279,
            "unit": "ns/op",
            "extra": "91128 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - B/op",
            "value": 10400,
            "unit": "B/op",
            "extra": "91128 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - allocs/op",
            "value": 27,
            "unit": "allocs/op",
            "extra": "91128 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt",
            "value": 161103,
            "unit": "ns/op\t   24176 B/op\t     118 allocs/op",
            "extra": "7246 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - ns/op",
            "value": 161103,
            "unit": "ns/op",
            "extra": "7246 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - B/op",
            "value": 24176,
            "unit": "B/op",
            "extra": "7246 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - allocs/op",
            "value": 118,
            "unit": "allocs/op",
            "extra": "7246 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement",
            "value": 90477,
            "unit": "ns/op\t    1617 B/op\t      24 allocs/op",
            "extra": "13252 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - ns/op",
            "value": 90477,
            "unit": "ns/op",
            "extra": "13252 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - B/op",
            "value": 1617,
            "unit": "B/op",
            "extra": "13252 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - allocs/op",
            "value": 24,
            "unit": "allocs/op",
            "extra": "13252 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey",
            "value": 91302,
            "unit": "ns/op\t    3296 B/op\t      44 allocs/op",
            "extra": "12901 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - ns/op",
            "value": 91302,
            "unit": "ns/op",
            "extra": "12901 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - B/op",
            "value": 3296,
            "unit": "B/op",
            "extra": "12901 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - allocs/op",
            "value": 44,
            "unit": "allocs/op",
            "extra": "12901 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap",
            "value": 972.3,
            "unit": "ns/op\t     736 B/op\t       8 allocs/op",
            "extra": "1233798 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - ns/op",
            "value": 972.3,
            "unit": "ns/op",
            "extra": "1233798 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - B/op",
            "value": 736,
            "unit": "B/op",
            "extra": "1233798 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "1233798 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap",
            "value": 1003,
            "unit": "ns/op\t     720 B/op\t       8 allocs/op",
            "extra": "1000000 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - ns/op",
            "value": 1003,
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
            "value": 727.4,
            "unit": "ns/op\t    2448 B/op\t       4 allocs/op",
            "extra": "1685384 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - ns/op",
            "value": 727.4,
            "unit": "ns/op",
            "extra": "1685384 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - B/op",
            "value": 2448,
            "unit": "B/op",
            "extra": "1685384 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - allocs/op",
            "value": 4,
            "unit": "allocs/op",
            "extra": "1685384 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline",
            "value": 96023,
            "unit": "ns/op\t   13432 B/op\t     117 allocs/op",
            "extra": "12240 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - ns/op",
            "value": 96023,
            "unit": "ns/op",
            "extra": "12240 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - B/op",
            "value": 13432,
            "unit": "B/op",
            "extra": "12240 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - allocs/op",
            "value": 117,
            "unit": "allocs/op",
            "extra": "12240 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline",
            "value": 59975,
            "unit": "ns/op\t   15176 B/op\t     205 allocs/op",
            "extra": "19934 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - ns/op",
            "value": 59975,
            "unit": "ns/op",
            "extra": "19934 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - B/op",
            "value": 15176,
            "unit": "B/op",
            "extra": "19934 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - allocs/op",
            "value": 205,
            "unit": "allocs/op",
            "extra": "19934 times\n4 procs"
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
          "id": "5b8109c4f283d1dd3a99f256f602c7b504582782",
          "message": "chore(deps): update all (#148)\n\nCo-authored-by: renovate[bot] <29139614+renovate[bot]@users.noreply.github.com>",
          "timestamp": "2026-10-08T16:38:00Z",
          "url": "https://github.com/moov-io/signedxml/commit/5b8109c4f283d1dd3a99f256f602c7b504582782"
        },
        "date": 1791548641254,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkEncryptElement",
            "value": 5630,
            "unit": "ns/op\t    8600 B/op\t      23 allocs/op",
            "extra": "216314 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - ns/op",
            "value": 5630,
            "unit": "ns/op",
            "extra": "216314 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - B/op",
            "value": 8600,
            "unit": "B/op",
            "extra": "216314 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - allocs/op",
            "value": 23,
            "unit": "allocs/op",
            "extra": "216314 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement",
            "value": 15402,
            "unit": "ns/op\t   10400 B/op\t      27 allocs/op",
            "extra": "77516 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - ns/op",
            "value": 15402,
            "unit": "ns/op",
            "extra": "77516 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - B/op",
            "value": 10400,
            "unit": "B/op",
            "extra": "77516 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - allocs/op",
            "value": 27,
            "unit": "allocs/op",
            "extra": "77516 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt",
            "value": 204922,
            "unit": "ns/op\t   24176 B/op\t     118 allocs/op",
            "extra": "5590 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - ns/op",
            "value": 204922,
            "unit": "ns/op",
            "extra": "5590 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - B/op",
            "value": 24176,
            "unit": "B/op",
            "extra": "5590 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - allocs/op",
            "value": 118,
            "unit": "allocs/op",
            "extra": "5590 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement",
            "value": 117187,
            "unit": "ns/op\t    1617 B/op\t      24 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - ns/op",
            "value": 117187,
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
            "value": 118392,
            "unit": "ns/op\t    3296 B/op\t      44 allocs/op",
            "extra": "9987 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - ns/op",
            "value": 118392,
            "unit": "ns/op",
            "extra": "9987 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - B/op",
            "value": 3296,
            "unit": "B/op",
            "extra": "9987 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - allocs/op",
            "value": 44,
            "unit": "allocs/op",
            "extra": "9987 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap",
            "value": 1274,
            "unit": "ns/op\t     736 B/op\t       8 allocs/op",
            "extra": "952765 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - ns/op",
            "value": 1274,
            "unit": "ns/op",
            "extra": "952765 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - B/op",
            "value": 736,
            "unit": "B/op",
            "extra": "952765 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "952765 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap",
            "value": 1272,
            "unit": "ns/op\t     720 B/op\t       8 allocs/op",
            "extra": "933145 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - ns/op",
            "value": 1272,
            "unit": "ns/op",
            "extra": "933145 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - B/op",
            "value": 720,
            "unit": "B/op",
            "extra": "933145 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "933145 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt",
            "value": 900.1,
            "unit": "ns/op\t    2448 B/op\t       4 allocs/op",
            "extra": "1336598 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - ns/op",
            "value": 900.1,
            "unit": "ns/op",
            "extra": "1336598 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - B/op",
            "value": 2448,
            "unit": "B/op",
            "extra": "1336598 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - allocs/op",
            "value": 4,
            "unit": "allocs/op",
            "extra": "1336598 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline",
            "value": 129136,
            "unit": "ns/op\t   13432 B/op\t     117 allocs/op",
            "extra": "9243 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - ns/op",
            "value": 129136,
            "unit": "ns/op",
            "extra": "9243 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - B/op",
            "value": 13432,
            "unit": "B/op",
            "extra": "9243 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - allocs/op",
            "value": 117,
            "unit": "allocs/op",
            "extra": "9243 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline",
            "value": 77018,
            "unit": "ns/op\t   15176 B/op\t     205 allocs/op",
            "extra": "15276 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - ns/op",
            "value": 77018,
            "unit": "ns/op",
            "extra": "15276 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - B/op",
            "value": 15176,
            "unit": "B/op",
            "extra": "15276 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - allocs/op",
            "value": 205,
            "unit": "allocs/op",
            "extra": "15276 times\n4 procs"
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
          "id": "e36c0731e4712c1deffcff17c648d1304477de82",
          "message": "fix(deps): update module golang.org/x/crypto to v0.58.0 (#149)\n\nCo-authored-by: renovate[bot] <29139614+renovate[bot]@users.noreply.github.com>",
          "timestamp": "2026-10-09T19:40:29Z",
          "url": "https://github.com/moov-io/signedxml/commit/e36c0731e4712c1deffcff17c648d1304477de82"
        },
        "date": 1791632579299,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkEncryptElement",
            "value": 3074,
            "unit": "ns/op\t    8600 B/op\t      23 allocs/op",
            "extra": "395847 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - ns/op",
            "value": 3074,
            "unit": "ns/op",
            "extra": "395847 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - B/op",
            "value": 8600,
            "unit": "B/op",
            "extra": "395847 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - allocs/op",
            "value": 23,
            "unit": "allocs/op",
            "extra": "395847 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement",
            "value": 8701,
            "unit": "ns/op\t   10400 B/op\t      27 allocs/op",
            "extra": "143934 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - ns/op",
            "value": 8701,
            "unit": "ns/op",
            "extra": "143934 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - B/op",
            "value": 10400,
            "unit": "B/op",
            "extra": "143934 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - allocs/op",
            "value": 27,
            "unit": "allocs/op",
            "extra": "143934 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt",
            "value": 102510,
            "unit": "ns/op\t   24176 B/op\t     118 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - ns/op",
            "value": 102510,
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
            "value": 58992,
            "unit": "ns/op\t    1617 B/op\t      24 allocs/op",
            "extra": "20337 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - ns/op",
            "value": 58992,
            "unit": "ns/op",
            "extra": "20337 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - B/op",
            "value": 1617,
            "unit": "B/op",
            "extra": "20337 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - allocs/op",
            "value": 24,
            "unit": "allocs/op",
            "extra": "20337 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey",
            "value": 60546,
            "unit": "ns/op\t    3296 B/op\t      44 allocs/op",
            "extra": "20037 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - ns/op",
            "value": 60546,
            "unit": "ns/op",
            "extra": "20037 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - B/op",
            "value": 3296,
            "unit": "B/op",
            "extra": "20037 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - allocs/op",
            "value": 44,
            "unit": "allocs/op",
            "extra": "20037 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap",
            "value": 754,
            "unit": "ns/op\t     736 B/op\t       8 allocs/op",
            "extra": "1596266 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - ns/op",
            "value": 754,
            "unit": "ns/op",
            "extra": "1596266 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - B/op",
            "value": 736,
            "unit": "B/op",
            "extra": "1596266 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "1596266 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap",
            "value": 752.9,
            "unit": "ns/op\t     720 B/op\t       8 allocs/op",
            "extra": "1589428 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - ns/op",
            "value": 752.9,
            "unit": "ns/op",
            "extra": "1589428 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - B/op",
            "value": 720,
            "unit": "B/op",
            "extra": "1589428 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "1589428 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt",
            "value": 569,
            "unit": "ns/op\t    2448 B/op\t       4 allocs/op",
            "extra": "2115487 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - ns/op",
            "value": 569,
            "unit": "ns/op",
            "extra": "2115487 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - B/op",
            "value": 2448,
            "unit": "B/op",
            "extra": "2115487 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - allocs/op",
            "value": 4,
            "unit": "allocs/op",
            "extra": "2115487 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline",
            "value": 63029,
            "unit": "ns/op\t   13432 B/op\t     117 allocs/op",
            "extra": "18220 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - ns/op",
            "value": 63029,
            "unit": "ns/op",
            "extra": "18220 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - B/op",
            "value": 13432,
            "unit": "B/op",
            "extra": "18220 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - allocs/op",
            "value": 117,
            "unit": "allocs/op",
            "extra": "18220 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline",
            "value": 41901,
            "unit": "ns/op\t   15176 B/op\t     205 allocs/op",
            "extra": "30132 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - ns/op",
            "value": 41901,
            "unit": "ns/op",
            "extra": "30132 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - B/op",
            "value": 15176,
            "unit": "B/op",
            "extra": "30132 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - allocs/op",
            "value": 205,
            "unit": "allocs/op",
            "extra": "30132 times\n4 procs"
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
          "id": "e36c0731e4712c1deffcff17c648d1304477de82",
          "message": "fix(deps): update module golang.org/x/crypto to v0.58.0 (#149)\n\nCo-authored-by: renovate[bot] <29139614+renovate[bot]@users.noreply.github.com>",
          "timestamp": "2026-10-09T19:40:29Z",
          "url": "https://github.com/moov-io/signedxml/commit/e36c0731e4712c1deffcff17c648d1304477de82"
        },
        "date": 1791719729234,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkEncryptElement",
            "value": 3450,
            "unit": "ns/op\t    8600 B/op\t      23 allocs/op",
            "extra": "353534 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - ns/op",
            "value": 3450,
            "unit": "ns/op",
            "extra": "353534 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - B/op",
            "value": 8600,
            "unit": "B/op",
            "extra": "353534 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - allocs/op",
            "value": 23,
            "unit": "allocs/op",
            "extra": "353534 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement",
            "value": 9473,
            "unit": "ns/op\t   10400 B/op\t      27 allocs/op",
            "extra": "128707 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - ns/op",
            "value": 9473,
            "unit": "ns/op",
            "extra": "128707 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - B/op",
            "value": 10400,
            "unit": "B/op",
            "extra": "128707 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - allocs/op",
            "value": 27,
            "unit": "allocs/op",
            "extra": "128707 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt",
            "value": 116378,
            "unit": "ns/op\t   24176 B/op\t     118 allocs/op",
            "extra": "9156 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - ns/op",
            "value": 116378,
            "unit": "ns/op",
            "extra": "9156 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - B/op",
            "value": 24176,
            "unit": "B/op",
            "extra": "9156 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - allocs/op",
            "value": 118,
            "unit": "allocs/op",
            "extra": "9156 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement",
            "value": 67574,
            "unit": "ns/op\t    1617 B/op\t      24 allocs/op",
            "extra": "16888 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - ns/op",
            "value": 67574,
            "unit": "ns/op",
            "extra": "16888 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - B/op",
            "value": 1617,
            "unit": "B/op",
            "extra": "16888 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - allocs/op",
            "value": 24,
            "unit": "allocs/op",
            "extra": "16888 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey",
            "value": 70784,
            "unit": "ns/op\t    3296 B/op\t      44 allocs/op",
            "extra": "17088 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - ns/op",
            "value": 70784,
            "unit": "ns/op",
            "extra": "17088 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - B/op",
            "value": 3296,
            "unit": "B/op",
            "extra": "17088 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - allocs/op",
            "value": 44,
            "unit": "allocs/op",
            "extra": "17088 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap",
            "value": 856.6,
            "unit": "ns/op\t     736 B/op\t       8 allocs/op",
            "extra": "1413144 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - ns/op",
            "value": 856.6,
            "unit": "ns/op",
            "extra": "1413144 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - B/op",
            "value": 736,
            "unit": "B/op",
            "extra": "1413144 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "1413144 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap",
            "value": 854.2,
            "unit": "ns/op\t     720 B/op\t       8 allocs/op",
            "extra": "1397251 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - ns/op",
            "value": 854.2,
            "unit": "ns/op",
            "extra": "1397251 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - B/op",
            "value": 720,
            "unit": "B/op",
            "extra": "1397251 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "1397251 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt",
            "value": 650.1,
            "unit": "ns/op\t    2448 B/op\t       4 allocs/op",
            "extra": "1858970 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - ns/op",
            "value": 650.1,
            "unit": "ns/op",
            "extra": "1858970 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - B/op",
            "value": 2448,
            "unit": "B/op",
            "extra": "1858970 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - allocs/op",
            "value": 4,
            "unit": "allocs/op",
            "extra": "1858970 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline",
            "value": 71547,
            "unit": "ns/op\t   13432 B/op\t     117 allocs/op",
            "extra": "16526 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - ns/op",
            "value": 71547,
            "unit": "ns/op",
            "extra": "16526 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - B/op",
            "value": 13432,
            "unit": "B/op",
            "extra": "16526 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - allocs/op",
            "value": 117,
            "unit": "allocs/op",
            "extra": "16526 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline",
            "value": 46214,
            "unit": "ns/op\t   15176 B/op\t     205 allocs/op",
            "extra": "26316 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - ns/op",
            "value": 46214,
            "unit": "ns/op",
            "extra": "26316 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - B/op",
            "value": 15176,
            "unit": "B/op",
            "extra": "26316 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - allocs/op",
            "value": 205,
            "unit": "allocs/op",
            "extra": "26316 times\n4 procs"
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
          "id": "e36c0731e4712c1deffcff17c648d1304477de82",
          "message": "fix(deps): update module golang.org/x/crypto to v0.58.0 (#149)\n\nCo-authored-by: renovate[bot] <29139614+renovate[bot]@users.noreply.github.com>",
          "timestamp": "2026-10-09T19:40:29Z",
          "url": "https://github.com/moov-io/signedxml/commit/e36c0731e4712c1deffcff17c648d1304477de82"
        },
        "date": 1791813951580,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkEncryptElement",
            "value": 4492,
            "unit": "ns/op\t    8600 B/op\t      23 allocs/op",
            "extra": "251409 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - ns/op",
            "value": 4492,
            "unit": "ns/op",
            "extra": "251409 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - B/op",
            "value": 8600,
            "unit": "B/op",
            "extra": "251409 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - allocs/op",
            "value": 23,
            "unit": "allocs/op",
            "extra": "251409 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement",
            "value": 12014,
            "unit": "ns/op\t   10400 B/op\t      27 allocs/op",
            "extra": "95998 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - ns/op",
            "value": 12014,
            "unit": "ns/op",
            "extra": "95998 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - B/op",
            "value": 10400,
            "unit": "B/op",
            "extra": "95998 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - allocs/op",
            "value": 27,
            "unit": "allocs/op",
            "extra": "95998 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt",
            "value": 155833,
            "unit": "ns/op\t   24176 B/op\t     118 allocs/op",
            "extra": "7354 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - ns/op",
            "value": 155833,
            "unit": "ns/op",
            "extra": "7354 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - B/op",
            "value": 24176,
            "unit": "B/op",
            "extra": "7354 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - allocs/op",
            "value": 118,
            "unit": "allocs/op",
            "extra": "7354 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement",
            "value": 89991,
            "unit": "ns/op\t    1617 B/op\t      24 allocs/op",
            "extra": "13318 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - ns/op",
            "value": 89991,
            "unit": "ns/op",
            "extra": "13318 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - B/op",
            "value": 1617,
            "unit": "B/op",
            "extra": "13318 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - allocs/op",
            "value": 24,
            "unit": "allocs/op",
            "extra": "13318 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey",
            "value": 91312,
            "unit": "ns/op\t    3296 B/op\t      44 allocs/op",
            "extra": "13132 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - ns/op",
            "value": 91312,
            "unit": "ns/op",
            "extra": "13132 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - B/op",
            "value": 3296,
            "unit": "B/op",
            "extra": "13132 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - allocs/op",
            "value": 44,
            "unit": "allocs/op",
            "extra": "13132 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap",
            "value": 975.4,
            "unit": "ns/op\t     736 B/op\t       8 allocs/op",
            "extra": "1234242 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - ns/op",
            "value": 975.4,
            "unit": "ns/op",
            "extra": "1234242 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - B/op",
            "value": 736,
            "unit": "B/op",
            "extra": "1234242 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "1234242 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap",
            "value": 985.9,
            "unit": "ns/op\t     720 B/op\t       8 allocs/op",
            "extra": "1209538 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - ns/op",
            "value": 985.9,
            "unit": "ns/op",
            "extra": "1209538 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - B/op",
            "value": 720,
            "unit": "B/op",
            "extra": "1209538 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "1209538 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt",
            "value": 710.1,
            "unit": "ns/op\t    2448 B/op\t       4 allocs/op",
            "extra": "1675184 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - ns/op",
            "value": 710.1,
            "unit": "ns/op",
            "extra": "1675184 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - B/op",
            "value": 2448,
            "unit": "B/op",
            "extra": "1675184 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - allocs/op",
            "value": 4,
            "unit": "allocs/op",
            "extra": "1675184 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline",
            "value": 96749,
            "unit": "ns/op\t   13432 B/op\t     117 allocs/op",
            "extra": "12416 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - ns/op",
            "value": 96749,
            "unit": "ns/op",
            "extra": "12416 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - B/op",
            "value": 13432,
            "unit": "B/op",
            "extra": "12416 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - allocs/op",
            "value": 117,
            "unit": "allocs/op",
            "extra": "12416 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline",
            "value": 59388,
            "unit": "ns/op\t   15176 B/op\t     205 allocs/op",
            "extra": "20070 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - ns/op",
            "value": 59388,
            "unit": "ns/op",
            "extra": "20070 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - B/op",
            "value": 15176,
            "unit": "B/op",
            "extra": "20070 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - allocs/op",
            "value": 205,
            "unit": "allocs/op",
            "extra": "20070 times\n4 procs"
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
          "id": "e36c0731e4712c1deffcff17c648d1304477de82",
          "message": "fix(deps): update module golang.org/x/crypto to v0.58.0 (#149)\n\nCo-authored-by: renovate[bot] <29139614+renovate[bot]@users.noreply.github.com>",
          "timestamp": "2026-10-09T19:40:29Z",
          "url": "https://github.com/moov-io/signedxml/commit/e36c0731e4712c1deffcff17c648d1304477de82"
        },
        "date": 1791897510689,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkEncryptElement",
            "value": 5131,
            "unit": "ns/op\t    8600 B/op\t      23 allocs/op",
            "extra": "218727 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - ns/op",
            "value": 5131,
            "unit": "ns/op",
            "extra": "218727 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - B/op",
            "value": 8600,
            "unit": "B/op",
            "extra": "218727 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - allocs/op",
            "value": 23,
            "unit": "allocs/op",
            "extra": "218727 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement",
            "value": 15141,
            "unit": "ns/op\t   10400 B/op\t      27 allocs/op",
            "extra": "79941 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - ns/op",
            "value": 15141,
            "unit": "ns/op",
            "extra": "79941 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - B/op",
            "value": 10400,
            "unit": "B/op",
            "extra": "79941 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - allocs/op",
            "value": 27,
            "unit": "allocs/op",
            "extra": "79941 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt",
            "value": 185788,
            "unit": "ns/op\t   24176 B/op\t     118 allocs/op",
            "extra": "6320 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - ns/op",
            "value": 185788,
            "unit": "ns/op",
            "extra": "6320 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - B/op",
            "value": 24176,
            "unit": "B/op",
            "extra": "6320 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - allocs/op",
            "value": 118,
            "unit": "allocs/op",
            "extra": "6320 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement",
            "value": 108819,
            "unit": "ns/op\t    1617 B/op\t      24 allocs/op",
            "extra": "9504 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - ns/op",
            "value": 108819,
            "unit": "ns/op",
            "extra": "9504 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - B/op",
            "value": 1617,
            "unit": "B/op",
            "extra": "9504 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - allocs/op",
            "value": 24,
            "unit": "allocs/op",
            "extra": "9504 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey",
            "value": 107325,
            "unit": "ns/op\t    3296 B/op\t      44 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - ns/op",
            "value": 107325,
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
            "value": 1223,
            "unit": "ns/op\t     736 B/op\t       8 allocs/op",
            "extra": "872890 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - ns/op",
            "value": 1223,
            "unit": "ns/op",
            "extra": "872890 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - B/op",
            "value": 736,
            "unit": "B/op",
            "extra": "872890 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "872890 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap",
            "value": 1248,
            "unit": "ns/op\t     720 B/op\t       8 allocs/op",
            "extra": "848182 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - ns/op",
            "value": 1248,
            "unit": "ns/op",
            "extra": "848182 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - B/op",
            "value": 720,
            "unit": "B/op",
            "extra": "848182 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "848182 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt",
            "value": 884.9,
            "unit": "ns/op\t    2448 B/op\t       4 allocs/op",
            "extra": "1346036 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - ns/op",
            "value": 884.9,
            "unit": "ns/op",
            "extra": "1346036 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - B/op",
            "value": 2448,
            "unit": "B/op",
            "extra": "1346036 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - allocs/op",
            "value": 4,
            "unit": "allocs/op",
            "extra": "1346036 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline",
            "value": 113005,
            "unit": "ns/op\t   13432 B/op\t     117 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - ns/op",
            "value": 113005,
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
            "value": 71847,
            "unit": "ns/op\t   15176 B/op\t     205 allocs/op",
            "extra": "16842 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - ns/op",
            "value": 71847,
            "unit": "ns/op",
            "extra": "16842 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - B/op",
            "value": 15176,
            "unit": "B/op",
            "extra": "16842 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - allocs/op",
            "value": 205,
            "unit": "allocs/op",
            "extra": "16842 times\n4 procs"
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
          "id": "e36c0731e4712c1deffcff17c648d1304477de82",
          "message": "fix(deps): update module golang.org/x/crypto to v0.58.0 (#149)\n\nCo-authored-by: renovate[bot] <29139614+renovate[bot]@users.noreply.github.com>",
          "timestamp": "2026-10-09T19:40:29Z",
          "url": "https://github.com/moov-io/signedxml/commit/e36c0731e4712c1deffcff17c648d1304477de82"
        },
        "date": 1791975538452,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkEncryptElement",
            "value": 5501,
            "unit": "ns/op\t    8600 B/op\t      23 allocs/op",
            "extra": "231648 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - ns/op",
            "value": 5501,
            "unit": "ns/op",
            "extra": "231648 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - B/op",
            "value": 8600,
            "unit": "B/op",
            "extra": "231648 times\n4 procs"
          },
          {
            "name": "BenchmarkEncryptElement - allocs/op",
            "value": 23,
            "unit": "allocs/op",
            "extra": "231648 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement",
            "value": 15476,
            "unit": "ns/op\t   10400 B/op\t      27 allocs/op",
            "extra": "74923 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - ns/op",
            "value": 15476,
            "unit": "ns/op",
            "extra": "74923 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - B/op",
            "value": 10400,
            "unit": "B/op",
            "extra": "74923 times\n4 procs"
          },
          {
            "name": "BenchmarkDecryptElement - allocs/op",
            "value": 27,
            "unit": "allocs/op",
            "extra": "74923 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt",
            "value": 187457,
            "unit": "ns/op\t   24176 B/op\t     118 allocs/op",
            "extra": "6246 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - ns/op",
            "value": 187457,
            "unit": "ns/op",
            "extra": "6246 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - B/op",
            "value": 24176,
            "unit": "B/op",
            "extra": "6246 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - allocs/op",
            "value": 118,
            "unit": "allocs/op",
            "extra": "6246 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement",
            "value": 105869,
            "unit": "ns/op\t    1617 B/op\t      24 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - ns/op",
            "value": 105869,
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
            "value": 108189,
            "unit": "ns/op\t    3296 B/op\t      44 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - ns/op",
            "value": 108189,
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
            "value": 1241,
            "unit": "ns/op\t     736 B/op\t       8 allocs/op",
            "extra": "877996 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - ns/op",
            "value": 1241,
            "unit": "ns/op",
            "extra": "877996 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - B/op",
            "value": 736,
            "unit": "B/op",
            "extra": "877996 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "877996 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap",
            "value": 1253,
            "unit": "ns/op\t     720 B/op\t       8 allocs/op",
            "extra": "873438 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - ns/op",
            "value": 1253,
            "unit": "ns/op",
            "extra": "873438 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - B/op",
            "value": 720,
            "unit": "B/op",
            "extra": "873438 times\n4 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "873438 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt",
            "value": 936.4,
            "unit": "ns/op\t    2448 B/op\t       4 allocs/op",
            "extra": "1321530 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - ns/op",
            "value": 936.4,
            "unit": "ns/op",
            "extra": "1321530 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - B/op",
            "value": 2448,
            "unit": "B/op",
            "extra": "1321530 times\n4 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - allocs/op",
            "value": 4,
            "unit": "allocs/op",
            "extra": "1321530 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline",
            "value": 112402,
            "unit": "ns/op\t   13432 B/op\t     117 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - ns/op",
            "value": 112402,
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
            "value": 73031,
            "unit": "ns/op\t   15176 B/op\t     205 allocs/op",
            "extra": "15422 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - ns/op",
            "value": 73031,
            "unit": "ns/op",
            "extra": "15422 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - B/op",
            "value": 15176,
            "unit": "B/op",
            "extra": "15422 times\n4 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - allocs/op",
            "value": 205,
            "unit": "allocs/op",
            "extra": "15422 times\n4 procs"
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
            "name": "Adam Shannon",
            "username": "adamdecaf",
            "email": "adamkshannon@gmail.com"
          },
          "id": "14c3e917e28a0f4eec3a8c3c8fe38b3410c1f282",
          "message": "ci: store median of 6 bench samples at 2 CPUs\n\nRun go test -count=6 -cpu=2 and collapse each benchmark to a median\nline before github-action-benchmark records it. Raise alert-threshold\nto 150% and pin ubuntu-24.04.",
          "timestamp": "2026-10-14T14:53:19Z",
          "url": "https://github.com/moov-io/signedxml/commit/14c3e917e28a0f4eec3a8c3c8fe38b3410c1f282"
        },
        "date": 1791989811512,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkEncryptElement",
            "value": 4739.5,
            "unit": "ns/op\t8600 B/op\t23 allocs/op",
            "extra": "244338 times\n2 procs"
          },
          {
            "name": "BenchmarkEncryptElement - ns/op",
            "value": 4739.5,
            "unit": "ns/op",
            "extra": "244338 times\n2 procs"
          },
          {
            "name": "BenchmarkEncryptElement - B/op",
            "value": 8600,
            "unit": "B/op",
            "extra": "244338 times\n2 procs"
          },
          {
            "name": "BenchmarkEncryptElement - allocs/op",
            "value": 23,
            "unit": "allocs/op",
            "extra": "244338 times\n2 procs"
          },
          {
            "name": "BenchmarkDecryptElement",
            "value": 14852.5,
            "unit": "ns/op\t10400 B/op\t27 allocs/op",
            "extra": "81894 times\n2 procs"
          },
          {
            "name": "BenchmarkDecryptElement - ns/op",
            "value": 14852.5,
            "unit": "ns/op",
            "extra": "81894 times\n2 procs"
          },
          {
            "name": "BenchmarkDecryptElement - B/op",
            "value": 10400,
            "unit": "B/op",
            "extra": "81894 times\n2 procs"
          },
          {
            "name": "BenchmarkDecryptElement - allocs/op",
            "value": 27,
            "unit": "allocs/op",
            "extra": "81894 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt",
            "value": 158116,
            "unit": "ns/op\t24176 B/op\t118 allocs/op",
            "extra": "7212 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - ns/op",
            "value": 158116,
            "unit": "ns/op",
            "extra": "7212 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - B/op",
            "value": 24176,
            "unit": "B/op",
            "extra": "7212 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - allocs/op",
            "value": 118,
            "unit": "allocs/op",
            "extra": "7212 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement",
            "value": 89569.5,
            "unit": "ns/op\t1617 B/op\t24 allocs/op",
            "extra": "13383 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - ns/op",
            "value": 89569.5,
            "unit": "ns/op",
            "extra": "13383 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - B/op",
            "value": 1617,
            "unit": "B/op",
            "extra": "13383 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - allocs/op",
            "value": 24,
            "unit": "allocs/op",
            "extra": "13383 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey",
            "value": 90787,
            "unit": "ns/op\t3296 B/op\t44 allocs/op",
            "extra": "13206 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - ns/op",
            "value": 90787,
            "unit": "ns/op",
            "extra": "13206 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - B/op",
            "value": 3296,
            "unit": "B/op",
            "extra": "13206 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - allocs/op",
            "value": 44,
            "unit": "allocs/op",
            "extra": "13206 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap",
            "value": 1058,
            "unit": "ns/op\t736 B/op\t8 allocs/op",
            "extra": "1000000 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - ns/op",
            "value": 1058,
            "unit": "ns/op",
            "extra": "1000000 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - B/op",
            "value": 736,
            "unit": "B/op",
            "extra": "1000000 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "1000000 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap",
            "value": 1073.5,
            "unit": "ns/op\t720 B/op\t8 allocs/op",
            "extra": "1000000 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - ns/op",
            "value": 1073.5,
            "unit": "ns/op",
            "extra": "1000000 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - B/op",
            "value": 720,
            "unit": "B/op",
            "extra": "1000000 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "1000000 times\n2 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt",
            "value": 815.3,
            "unit": "ns/op\t2448 B/op\t4 allocs/op",
            "extra": "1464789 times\n2 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - ns/op",
            "value": 815.3,
            "unit": "ns/op",
            "extra": "1464789 times\n2 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - B/op",
            "value": 2448,
            "unit": "B/op",
            "extra": "1464789 times\n2 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - allocs/op",
            "value": 4,
            "unit": "allocs/op",
            "extra": "1464789 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline",
            "value": 95812.5,
            "unit": "ns/op\t13432 B/op\t117 allocs/op",
            "extra": "12513 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - ns/op",
            "value": 95812.5,
            "unit": "ns/op",
            "extra": "12513 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - B/op",
            "value": 13432,
            "unit": "B/op",
            "extra": "12513 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - allocs/op",
            "value": 117,
            "unit": "allocs/op",
            "extra": "12513 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline",
            "value": 62784.5,
            "unit": "ns/op\t15176 B/op\t205 allocs/op",
            "extra": "19064 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - ns/op",
            "value": 62784.5,
            "unit": "ns/op",
            "extra": "19064 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - B/op",
            "value": 15176,
            "unit": "B/op",
            "extra": "19064 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - allocs/op",
            "value": 205,
            "unit": "allocs/op",
            "extra": "19064 times\n2 procs"
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
            "name": "Adam Shannon",
            "username": "adamdecaf",
            "email": "adamkshannon@gmail.com"
          },
          "id": "17003e085b08f56c713f7ee241f57074d51d3eab",
          "message": "ci: keep bench.yml on ubuntu-24.04\n\nRenovate automerged ubuntu-26.04 onto the benchmark workflow. Pin\n24.04 again and ignore that package in bench.yml so nightly samples\nstay comparable.",
          "timestamp": "2026-10-14T14:59:50Z",
          "url": "https://github.com/moov-io/signedxml/commit/17003e085b08f56c713f7ee241f57074d51d3eab"
        },
        "date": 1791991212787,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkEncryptElement",
            "value": 4185,
            "unit": "ns/op\t8600 B/op\t23 allocs/op",
            "extra": "282111 times\n2 procs"
          },
          {
            "name": "BenchmarkEncryptElement - ns/op",
            "value": 4185,
            "unit": "ns/op",
            "extra": "282111 times\n2 procs"
          },
          {
            "name": "BenchmarkEncryptElement - B/op",
            "value": 8600,
            "unit": "B/op",
            "extra": "282111 times\n2 procs"
          },
          {
            "name": "BenchmarkEncryptElement - allocs/op",
            "value": 23,
            "unit": "allocs/op",
            "extra": "282111 times\n2 procs"
          },
          {
            "name": "BenchmarkDecryptElement",
            "value": 11635,
            "unit": "ns/op\t10400 B/op\t27 allocs/op",
            "extra": "102596 times\n2 procs"
          },
          {
            "name": "BenchmarkDecryptElement - ns/op",
            "value": 11635,
            "unit": "ns/op",
            "extra": "102596 times\n2 procs"
          },
          {
            "name": "BenchmarkDecryptElement - B/op",
            "value": 10400,
            "unit": "B/op",
            "extra": "102596 times\n2 procs"
          },
          {
            "name": "BenchmarkDecryptElement - allocs/op",
            "value": 27,
            "unit": "allocs/op",
            "extra": "102596 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt",
            "value": 155968,
            "unit": "ns/op\t24176 B/op\t118 allocs/op",
            "extra": "7328 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - ns/op",
            "value": 155968,
            "unit": "ns/op",
            "extra": "7328 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - B/op",
            "value": 24176,
            "unit": "B/op",
            "extra": "7328 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - allocs/op",
            "value": 118,
            "unit": "allocs/op",
            "extra": "7328 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement",
            "value": 90206.5,
            "unit": "ns/op\t1617 B/op\t24 allocs/op",
            "extra": "13312 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - ns/op",
            "value": 90206.5,
            "unit": "ns/op",
            "extra": "13312 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - B/op",
            "value": 1617,
            "unit": "B/op",
            "extra": "13312 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - allocs/op",
            "value": 24,
            "unit": "allocs/op",
            "extra": "13312 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey",
            "value": 91382.5,
            "unit": "ns/op\t3296 B/op\t44 allocs/op",
            "extra": "13130 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - ns/op",
            "value": 91382.5,
            "unit": "ns/op",
            "extra": "13130 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - B/op",
            "value": 3296,
            "unit": "B/op",
            "extra": "13130 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - allocs/op",
            "value": 44,
            "unit": "allocs/op",
            "extra": "13130 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap",
            "value": 960.45,
            "unit": "ns/op\t736 B/op\t8 allocs/op",
            "extra": "1249956 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - ns/op",
            "value": 960.45,
            "unit": "ns/op",
            "extra": "1249956 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - B/op",
            "value": 736,
            "unit": "B/op",
            "extra": "1249956 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "1249956 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap",
            "value": 970.15,
            "unit": "ns/op\t720 B/op\t8 allocs/op",
            "extra": "1235859 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - ns/op",
            "value": 970.15,
            "unit": "ns/op",
            "extra": "1235859 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - B/op",
            "value": 720,
            "unit": "B/op",
            "extra": "1235859 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "1235859 times\n2 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt",
            "value": 678.1,
            "unit": "ns/op\t2448 B/op\t4 allocs/op",
            "extra": "1769385 times\n2 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - ns/op",
            "value": 678.1,
            "unit": "ns/op",
            "extra": "1769385 times\n2 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - B/op",
            "value": 2448,
            "unit": "B/op",
            "extra": "1769385 times\n2 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - allocs/op",
            "value": 4,
            "unit": "allocs/op",
            "extra": "1769385 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline",
            "value": 96120,
            "unit": "ns/op\t13432 B/op\t117 allocs/op",
            "extra": "12464 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - ns/op",
            "value": 96120,
            "unit": "ns/op",
            "extra": "12464 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - B/op",
            "value": 13432,
            "unit": "B/op",
            "extra": "12464 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - allocs/op",
            "value": 117,
            "unit": "allocs/op",
            "extra": "12464 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline",
            "value": 59600.5,
            "unit": "ns/op\t15176 B/op\t205 allocs/op",
            "extra": "20175 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - ns/op",
            "value": 59600.5,
            "unit": "ns/op",
            "extra": "20175 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - B/op",
            "value": 15176,
            "unit": "B/op",
            "extra": "20175 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - allocs/op",
            "value": 205,
            "unit": "allocs/op",
            "extra": "20175 times\n2 procs"
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
            "name": "Adam Shannon",
            "username": "adamdecaf",
            "email": "adamkshannon@gmail.com"
          },
          "id": "17003e085b08f56c713f7ee241f57074d51d3eab",
          "message": "ci: keep bench.yml on ubuntu-24.04\n\nRenovate automerged ubuntu-26.04 onto the benchmark workflow. Pin\n24.04 again and ignore that package in bench.yml so nightly samples\nstay comparable.",
          "timestamp": "2026-10-14T14:59:50Z",
          "url": "https://github.com/moov-io/signedxml/commit/17003e085b08f56c713f7ee241f57074d51d3eab"
        },
        "date": 1791991793635,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkEncryptElement",
            "value": 4584,
            "unit": "ns/op\t8600 B/op\t23 allocs/op",
            "extra": "264759 times\n2 procs"
          },
          {
            "name": "BenchmarkEncryptElement - ns/op",
            "value": 4584,
            "unit": "ns/op",
            "extra": "264759 times\n2 procs"
          },
          {
            "name": "BenchmarkEncryptElement - B/op",
            "value": 8600,
            "unit": "B/op",
            "extra": "264759 times\n2 procs"
          },
          {
            "name": "BenchmarkEncryptElement - allocs/op",
            "value": 23,
            "unit": "allocs/op",
            "extra": "264759 times\n2 procs"
          },
          {
            "name": "BenchmarkDecryptElement",
            "value": 14179,
            "unit": "ns/op\t10400 B/op\t27 allocs/op",
            "extra": "84462 times\n2 procs"
          },
          {
            "name": "BenchmarkDecryptElement - ns/op",
            "value": 14179,
            "unit": "ns/op",
            "extra": "84462 times\n2 procs"
          },
          {
            "name": "BenchmarkDecryptElement - B/op",
            "value": 10400,
            "unit": "B/op",
            "extra": "84462 times\n2 procs"
          },
          {
            "name": "BenchmarkDecryptElement - allocs/op",
            "value": 27,
            "unit": "allocs/op",
            "extra": "84462 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt",
            "value": 155351,
            "unit": "ns/op\t24176 B/op\t118 allocs/op",
            "extra": "7375 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - ns/op",
            "value": 155351,
            "unit": "ns/op",
            "extra": "7375 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - B/op",
            "value": 24176,
            "unit": "B/op",
            "extra": "7375 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - allocs/op",
            "value": 118,
            "unit": "allocs/op",
            "extra": "7375 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement",
            "value": 87261.5,
            "unit": "ns/op\t1617 B/op\t24 allocs/op",
            "extra": "13675 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - ns/op",
            "value": 87261.5,
            "unit": "ns/op",
            "extra": "13675 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - B/op",
            "value": 1617,
            "unit": "B/op",
            "extra": "13675 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - allocs/op",
            "value": 24,
            "unit": "allocs/op",
            "extra": "13675 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey",
            "value": 88393,
            "unit": "ns/op\t3296 B/op\t44 allocs/op",
            "extra": "13615 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - ns/op",
            "value": 88393,
            "unit": "ns/op",
            "extra": "13615 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - B/op",
            "value": 3296,
            "unit": "B/op",
            "extra": "13615 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - allocs/op",
            "value": 44,
            "unit": "allocs/op",
            "extra": "13615 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap",
            "value": 1021,
            "unit": "ns/op\t736 B/op\t8 allocs/op",
            "extra": "1000000 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - ns/op",
            "value": 1021,
            "unit": "ns/op",
            "extra": "1000000 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - B/op",
            "value": 736,
            "unit": "B/op",
            "extra": "1000000 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "1000000 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap",
            "value": 1026.5,
            "unit": "ns/op\t720 B/op\t8 allocs/op",
            "extra": "1000000 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - ns/op",
            "value": 1026.5,
            "unit": "ns/op",
            "extra": "1000000 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - B/op",
            "value": 720,
            "unit": "B/op",
            "extra": "1000000 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "1000000 times\n2 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt",
            "value": 799.7,
            "unit": "ns/op\t2448 B/op\t4 allocs/op",
            "extra": "1527109 times\n2 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - ns/op",
            "value": 799.7,
            "unit": "ns/op",
            "extra": "1527109 times\n2 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - B/op",
            "value": 2448,
            "unit": "B/op",
            "extra": "1527109 times\n2 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - allocs/op",
            "value": 4,
            "unit": "allocs/op",
            "extra": "1527109 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline",
            "value": 92940.5,
            "unit": "ns/op\t13432 B/op\t117 allocs/op",
            "extra": "12889 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - ns/op",
            "value": 92940.5,
            "unit": "ns/op",
            "extra": "12889 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - B/op",
            "value": 13432,
            "unit": "B/op",
            "extra": "12889 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - allocs/op",
            "value": 117,
            "unit": "allocs/op",
            "extra": "12889 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline",
            "value": 60338,
            "unit": "ns/op\t15176 B/op\t205 allocs/op",
            "extra": "19833 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - ns/op",
            "value": 60338,
            "unit": "ns/op",
            "extra": "19833 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - B/op",
            "value": 15176,
            "unit": "B/op",
            "extra": "19833 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - allocs/op",
            "value": 205,
            "unit": "allocs/op",
            "extra": "19833 times\n2 procs"
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
            "name": "Adam Shannon",
            "username": "adamdecaf",
            "email": "adamkshannon@gmail.com"
          },
          "id": "17003e085b08f56c713f7ee241f57074d51d3eab",
          "message": "ci: keep bench.yml on ubuntu-24.04\n\nRenovate automerged ubuntu-26.04 onto the benchmark workflow. Pin\n24.04 again and ignore that package in bench.yml so nightly samples\nstay comparable.",
          "timestamp": "2026-10-14T14:59:50Z",
          "url": "https://github.com/moov-io/signedxml/commit/17003e085b08f56c713f7ee241f57074d51d3eab"
        },
        "date": 1792060898904,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkEncryptElement",
            "value": 4603,
            "unit": "ns/op\t8600 B/op\t23 allocs/op",
            "extra": "251449 times\n2 procs"
          },
          {
            "name": "BenchmarkEncryptElement - ns/op",
            "value": 4603,
            "unit": "ns/op",
            "extra": "251449 times\n2 procs"
          },
          {
            "name": "BenchmarkEncryptElement - B/op",
            "value": 8600,
            "unit": "B/op",
            "extra": "251449 times\n2 procs"
          },
          {
            "name": "BenchmarkEncryptElement - allocs/op",
            "value": 23,
            "unit": "allocs/op",
            "extra": "251449 times\n2 procs"
          },
          {
            "name": "BenchmarkDecryptElement",
            "value": 13799.5,
            "unit": "ns/op\t10400 B/op\t27 allocs/op",
            "extra": "86510 times\n2 procs"
          },
          {
            "name": "BenchmarkDecryptElement - ns/op",
            "value": 13799.5,
            "unit": "ns/op",
            "extra": "86510 times\n2 procs"
          },
          {
            "name": "BenchmarkDecryptElement - B/op",
            "value": 10400,
            "unit": "B/op",
            "extra": "86510 times\n2 procs"
          },
          {
            "name": "BenchmarkDecryptElement - allocs/op",
            "value": 27,
            "unit": "allocs/op",
            "extra": "86510 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt",
            "value": 150234,
            "unit": "ns/op\t24176 B/op\t118 allocs/op",
            "extra": "7636 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - ns/op",
            "value": 150234,
            "unit": "ns/op",
            "extra": "7636 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - B/op",
            "value": 24176,
            "unit": "B/op",
            "extra": "7636 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - allocs/op",
            "value": 118,
            "unit": "allocs/op",
            "extra": "7636 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement",
            "value": 86610,
            "unit": "ns/op\t1617 B/op\t24 allocs/op",
            "extra": "13905 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - ns/op",
            "value": 86610,
            "unit": "ns/op",
            "extra": "13905 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - B/op",
            "value": 1617,
            "unit": "B/op",
            "extra": "13905 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - allocs/op",
            "value": 24,
            "unit": "allocs/op",
            "extra": "13905 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey",
            "value": 90310.5,
            "unit": "ns/op\t3296 B/op\t44 allocs/op",
            "extra": "13314 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - ns/op",
            "value": 90310.5,
            "unit": "ns/op",
            "extra": "13314 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - B/op",
            "value": 3296,
            "unit": "B/op",
            "extra": "13314 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - allocs/op",
            "value": 44,
            "unit": "allocs/op",
            "extra": "13314 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap",
            "value": 1057,
            "unit": "ns/op\t736 B/op\t8 allocs/op",
            "extra": "1000000 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - ns/op",
            "value": 1057,
            "unit": "ns/op",
            "extra": "1000000 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - B/op",
            "value": 736,
            "unit": "B/op",
            "extra": "1000000 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "1000000 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap",
            "value": 1055,
            "unit": "ns/op\t720 B/op\t8 allocs/op",
            "extra": "1000000 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - ns/op",
            "value": 1055,
            "unit": "ns/op",
            "extra": "1000000 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - B/op",
            "value": 720,
            "unit": "B/op",
            "extra": "1000000 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "1000000 times\n2 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt",
            "value": 797.9,
            "unit": "ns/op\t2448 B/op\t4 allocs/op",
            "extra": "1498474 times\n2 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - ns/op",
            "value": 797.9,
            "unit": "ns/op",
            "extra": "1498474 times\n2 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - B/op",
            "value": 2448,
            "unit": "B/op",
            "extra": "1498474 times\n2 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - allocs/op",
            "value": 4,
            "unit": "allocs/op",
            "extra": "1498474 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline",
            "value": 95909,
            "unit": "ns/op\t13432 B/op\t117 allocs/op",
            "extra": "12464 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - ns/op",
            "value": 95909,
            "unit": "ns/op",
            "extra": "12464 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - B/op",
            "value": 13432,
            "unit": "B/op",
            "extra": "12464 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - allocs/op",
            "value": 117,
            "unit": "allocs/op",
            "extra": "12464 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline",
            "value": 63382.5,
            "unit": "ns/op\t15176 B/op\t205 allocs/op",
            "extra": "19065 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - ns/op",
            "value": 63382.5,
            "unit": "ns/op",
            "extra": "19065 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - B/op",
            "value": 15176,
            "unit": "B/op",
            "extra": "19065 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - allocs/op",
            "value": 205,
            "unit": "allocs/op",
            "extra": "19065 times\n2 procs"
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
          "id": "204c583e79d4371e5264894222fefea1bb636849",
          "message": "chore(deps): update github/codeql-action action to v4.39.0 (#151)\n\nCo-authored-by: renovate[bot] <29139614+renovate[bot]@users.noreply.github.com>",
          "timestamp": "2026-10-15T17:00:41Z",
          "url": "https://github.com/moov-io/signedxml/commit/204c583e79d4371e5264894222fefea1bb636849"
        },
        "date": 1792146523883,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkEncryptElement",
            "value": 4177.5,
            "unit": "ns/op\t8600 B/op\t23 allocs/op",
            "extra": "276691 times\n2 procs"
          },
          {
            "name": "BenchmarkEncryptElement - ns/op",
            "value": 4177.5,
            "unit": "ns/op",
            "extra": "276691 times\n2 procs"
          },
          {
            "name": "BenchmarkEncryptElement - B/op",
            "value": 8600,
            "unit": "B/op",
            "extra": "276691 times\n2 procs"
          },
          {
            "name": "BenchmarkEncryptElement - allocs/op",
            "value": 23,
            "unit": "allocs/op",
            "extra": "276691 times\n2 procs"
          },
          {
            "name": "BenchmarkDecryptElement",
            "value": 11723,
            "unit": "ns/op\t10400 B/op\t27 allocs/op",
            "extra": "101150 times\n2 procs"
          },
          {
            "name": "BenchmarkDecryptElement - ns/op",
            "value": 11723,
            "unit": "ns/op",
            "extra": "101150 times\n2 procs"
          },
          {
            "name": "BenchmarkDecryptElement - B/op",
            "value": 10400,
            "unit": "B/op",
            "extra": "101150 times\n2 procs"
          },
          {
            "name": "BenchmarkDecryptElement - allocs/op",
            "value": 27,
            "unit": "allocs/op",
            "extra": "101150 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt",
            "value": 156403.5,
            "unit": "ns/op\t24176 B/op\t118 allocs/op",
            "extra": "7281 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - ns/op",
            "value": 156403.5,
            "unit": "ns/op",
            "extra": "7281 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - B/op",
            "value": 24176,
            "unit": "B/op",
            "extra": "7281 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - allocs/op",
            "value": 118,
            "unit": "allocs/op",
            "extra": "7281 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement",
            "value": 89958.5,
            "unit": "ns/op\t1617 B/op\t24 allocs/op",
            "extra": "13342 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - ns/op",
            "value": 89958.5,
            "unit": "ns/op",
            "extra": "13342 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - B/op",
            "value": 1617,
            "unit": "B/op",
            "extra": "13342 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - allocs/op",
            "value": 24,
            "unit": "allocs/op",
            "extra": "13342 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey",
            "value": 91252,
            "unit": "ns/op\t3296 B/op\t44 allocs/op",
            "extra": "13152 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - ns/op",
            "value": 91252,
            "unit": "ns/op",
            "extra": "13152 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - B/op",
            "value": 3296,
            "unit": "B/op",
            "extra": "13152 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - allocs/op",
            "value": 44,
            "unit": "allocs/op",
            "extra": "13152 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap",
            "value": 962.3,
            "unit": "ns/op\t736 B/op\t8 allocs/op",
            "extra": "1247976 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - ns/op",
            "value": 962.3,
            "unit": "ns/op",
            "extra": "1247976 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - B/op",
            "value": 736,
            "unit": "B/op",
            "extra": "1247976 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "1247976 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap",
            "value": 974.2,
            "unit": "ns/op\t720 B/op\t8 allocs/op",
            "extra": "1231836 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - ns/op",
            "value": 974.2,
            "unit": "ns/op",
            "extra": "1231836 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - B/op",
            "value": 720,
            "unit": "B/op",
            "extra": "1231836 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "1231836 times\n2 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt",
            "value": 682.15,
            "unit": "ns/op\t2448 B/op\t4 allocs/op",
            "extra": "1745408 times\n2 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - ns/op",
            "value": 682.15,
            "unit": "ns/op",
            "extra": "1745408 times\n2 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - B/op",
            "value": 2448,
            "unit": "B/op",
            "extra": "1745408 times\n2 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - allocs/op",
            "value": 4,
            "unit": "allocs/op",
            "extra": "1745408 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline",
            "value": 96564.5,
            "unit": "ns/op\t13432 B/op\t117 allocs/op",
            "extra": "12442 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - ns/op",
            "value": 96564.5,
            "unit": "ns/op",
            "extra": "12442 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - B/op",
            "value": 13432,
            "unit": "B/op",
            "extra": "12442 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - allocs/op",
            "value": 117,
            "unit": "allocs/op",
            "extra": "12442 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline",
            "value": 59805,
            "unit": "ns/op\t15176 B/op\t205 allocs/op",
            "extra": "20070 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - ns/op",
            "value": 59805,
            "unit": "ns/op",
            "extra": "20070 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - B/op",
            "value": 15176,
            "unit": "B/op",
            "extra": "20070 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - allocs/op",
            "value": 205,
            "unit": "allocs/op",
            "extra": "20070 times\n2 procs"
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
          "id": "204c583e79d4371e5264894222fefea1bb636849",
          "message": "chore(deps): update github/codeql-action action to v4.39.0 (#151)\n\nCo-authored-by: renovate[bot] <29139614+renovate[bot]@users.noreply.github.com>",
          "timestamp": "2026-10-15T17:00:41Z",
          "url": "https://github.com/moov-io/signedxml/commit/204c583e79d4371e5264894222fefea1bb636849"
        },
        "date": 1792231190947,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkEncryptElement",
            "value": 4833,
            "unit": "ns/op\t8600 B/op\t23 allocs/op",
            "extra": "246356 times\n2 procs"
          },
          {
            "name": "BenchmarkEncryptElement - ns/op",
            "value": 4833,
            "unit": "ns/op",
            "extra": "246356 times\n2 procs"
          },
          {
            "name": "BenchmarkEncryptElement - B/op",
            "value": 8600,
            "unit": "B/op",
            "extra": "246356 times\n2 procs"
          },
          {
            "name": "BenchmarkEncryptElement - allocs/op",
            "value": 23,
            "unit": "allocs/op",
            "extra": "246356 times\n2 procs"
          },
          {
            "name": "BenchmarkDecryptElement",
            "value": 14708.5,
            "unit": "ns/op\t10400 B/op\t27 allocs/op",
            "extra": "80294 times\n2 procs"
          },
          {
            "name": "BenchmarkDecryptElement - ns/op",
            "value": 14708.5,
            "unit": "ns/op",
            "extra": "80294 times\n2 procs"
          },
          {
            "name": "BenchmarkDecryptElement - B/op",
            "value": 10400,
            "unit": "B/op",
            "extra": "80294 times\n2 procs"
          },
          {
            "name": "BenchmarkDecryptElement - allocs/op",
            "value": 27,
            "unit": "allocs/op",
            "extra": "80294 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt",
            "value": 158066,
            "unit": "ns/op\t24176 B/op\t118 allocs/op",
            "extra": "7257 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - ns/op",
            "value": 158066,
            "unit": "ns/op",
            "extra": "7257 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - B/op",
            "value": 24176,
            "unit": "B/op",
            "extra": "7257 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - allocs/op",
            "value": 118,
            "unit": "allocs/op",
            "extra": "7257 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement",
            "value": 89601,
            "unit": "ns/op\t1617 B/op\t24 allocs/op",
            "extra": "13366 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - ns/op",
            "value": 89601,
            "unit": "ns/op",
            "extra": "13366 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - B/op",
            "value": 1617,
            "unit": "B/op",
            "extra": "13366 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - allocs/op",
            "value": 24,
            "unit": "allocs/op",
            "extra": "13366 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey",
            "value": 90989,
            "unit": "ns/op\t3296 B/op\t44 allocs/op",
            "extra": "13174 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - ns/op",
            "value": 90989,
            "unit": "ns/op",
            "extra": "13174 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - B/op",
            "value": 3296,
            "unit": "B/op",
            "extra": "13174 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - allocs/op",
            "value": 44,
            "unit": "allocs/op",
            "extra": "13174 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap",
            "value": 1065.5,
            "unit": "ns/op\t736 B/op\t8 allocs/op",
            "extra": "1000000 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - ns/op",
            "value": 1065.5,
            "unit": "ns/op",
            "extra": "1000000 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - B/op",
            "value": 736,
            "unit": "B/op",
            "extra": "1000000 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "1000000 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap",
            "value": 1077.5,
            "unit": "ns/op\t720 B/op\t8 allocs/op",
            "extra": "1000000 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - ns/op",
            "value": 1077.5,
            "unit": "ns/op",
            "extra": "1000000 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - B/op",
            "value": 720,
            "unit": "B/op",
            "extra": "1000000 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "1000000 times\n2 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt",
            "value": 802.1,
            "unit": "ns/op\t2448 B/op\t4 allocs/op",
            "extra": "1492429 times\n2 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - ns/op",
            "value": 802.1,
            "unit": "ns/op",
            "extra": "1492429 times\n2 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - B/op",
            "value": 2448,
            "unit": "B/op",
            "extra": "1492429 times\n2 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - allocs/op",
            "value": 4,
            "unit": "allocs/op",
            "extra": "1492429 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline",
            "value": 96422,
            "unit": "ns/op\t13432 B/op\t117 allocs/op",
            "extra": "12403 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - ns/op",
            "value": 96422,
            "unit": "ns/op",
            "extra": "12403 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - B/op",
            "value": 13432,
            "unit": "B/op",
            "extra": "12403 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - allocs/op",
            "value": 117,
            "unit": "allocs/op",
            "extra": "12403 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline",
            "value": 63205.5,
            "unit": "ns/op\t15176 B/op\t205 allocs/op",
            "extra": "19000 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - ns/op",
            "value": 63205.5,
            "unit": "ns/op",
            "extra": "19000 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - B/op",
            "value": 15176,
            "unit": "B/op",
            "extra": "19000 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - allocs/op",
            "value": 205,
            "unit": "allocs/op",
            "extra": "19000 times\n2 procs"
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
          "id": "204c583e79d4371e5264894222fefea1bb636849",
          "message": "chore(deps): update github/codeql-action action to v4.39.0 (#151)\n\nCo-authored-by: renovate[bot] <29139614+renovate[bot]@users.noreply.github.com>",
          "timestamp": "2026-10-15T17:00:41Z",
          "url": "https://github.com/moov-io/signedxml/commit/204c583e79d4371e5264894222fefea1bb636849"
        },
        "date": 1792318360753,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkEncryptElement",
            "value": 5110.5,
            "unit": "ns/op\t8600 B/op\t23 allocs/op",
            "extra": "236439 times\n2 procs"
          },
          {
            "name": "BenchmarkEncryptElement - ns/op",
            "value": 5110.5,
            "unit": "ns/op",
            "extra": "236439 times\n2 procs"
          },
          {
            "name": "BenchmarkEncryptElement - B/op",
            "value": 8600,
            "unit": "B/op",
            "extra": "236439 times\n2 procs"
          },
          {
            "name": "BenchmarkEncryptElement - allocs/op",
            "value": 23,
            "unit": "allocs/op",
            "extra": "236439 times\n2 procs"
          },
          {
            "name": "BenchmarkDecryptElement",
            "value": 15505.5,
            "unit": "ns/op\t10400 B/op\t27 allocs/op",
            "extra": "77017 times\n2 procs"
          },
          {
            "name": "BenchmarkDecryptElement - ns/op",
            "value": 15505.5,
            "unit": "ns/op",
            "extra": "77017 times\n2 procs"
          },
          {
            "name": "BenchmarkDecryptElement - B/op",
            "value": 10400,
            "unit": "B/op",
            "extra": "77017 times\n2 procs"
          },
          {
            "name": "BenchmarkDecryptElement - allocs/op",
            "value": 27,
            "unit": "allocs/op",
            "extra": "77017 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt",
            "value": 182553.5,
            "unit": "ns/op\t24176 B/op\t118 allocs/op",
            "extra": "6252 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - ns/op",
            "value": 182553.5,
            "unit": "ns/op",
            "extra": "6252 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - B/op",
            "value": 24176,
            "unit": "B/op",
            "extra": "6252 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - allocs/op",
            "value": 118,
            "unit": "allocs/op",
            "extra": "6252 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement",
            "value": 105570.5,
            "unit": "ns/op\t1617 B/op\t24 allocs/op",
            "extra": "10000 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - ns/op",
            "value": 105570.5,
            "unit": "ns/op",
            "extra": "10000 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - B/op",
            "value": 1617,
            "unit": "B/op",
            "extra": "10000 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - allocs/op",
            "value": 24,
            "unit": "allocs/op",
            "extra": "10000 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey",
            "value": 106921,
            "unit": "ns/op\t3296 B/op\t44 allocs/op",
            "extra": "10000 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - ns/op",
            "value": 106921,
            "unit": "ns/op",
            "extra": "10000 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - B/op",
            "value": 3296,
            "unit": "B/op",
            "extra": "10000 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - allocs/op",
            "value": 44,
            "unit": "allocs/op",
            "extra": "10000 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap",
            "value": 1211.5,
            "unit": "ns/op\t736 B/op\t8 allocs/op",
            "extra": "878038 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - ns/op",
            "value": 1211.5,
            "unit": "ns/op",
            "extra": "878038 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - B/op",
            "value": 736,
            "unit": "B/op",
            "extra": "878038 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "878038 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap",
            "value": 1238.5,
            "unit": "ns/op\t720 B/op\t8 allocs/op",
            "extra": "935859 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - ns/op",
            "value": 1238.5,
            "unit": "ns/op",
            "extra": "935859 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - B/op",
            "value": 720,
            "unit": "B/op",
            "extra": "935859 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "935859 times\n2 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt",
            "value": 830.05,
            "unit": "ns/op\t2448 B/op\t4 allocs/op",
            "extra": "1446354 times\n2 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - ns/op",
            "value": 830.05,
            "unit": "ns/op",
            "extra": "1446354 times\n2 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - B/op",
            "value": 2448,
            "unit": "B/op",
            "extra": "1446354 times\n2 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - allocs/op",
            "value": 4,
            "unit": "allocs/op",
            "extra": "1446354 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline",
            "value": 112171.5,
            "unit": "ns/op\t13432 B/op\t117 allocs/op",
            "extra": "10000 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - ns/op",
            "value": 112171.5,
            "unit": "ns/op",
            "extra": "10000 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - B/op",
            "value": 13432,
            "unit": "B/op",
            "extra": "10000 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - allocs/op",
            "value": 117,
            "unit": "allocs/op",
            "extra": "10000 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline",
            "value": 72162,
            "unit": "ns/op\t15176 B/op\t205 allocs/op",
            "extra": "16621 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - ns/op",
            "value": 72162,
            "unit": "ns/op",
            "extra": "16621 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - B/op",
            "value": 15176,
            "unit": "B/op",
            "extra": "16621 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - allocs/op",
            "value": 205,
            "unit": "allocs/op",
            "extra": "16621 times\n2 procs"
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
          "id": "204c583e79d4371e5264894222fefea1bb636849",
          "message": "chore(deps): update github/codeql-action action to v4.39.0 (#151)\n\nCo-authored-by: renovate[bot] <29139614+renovate[bot]@users.noreply.github.com>",
          "timestamp": "2026-10-15T17:00:41Z",
          "url": "https://github.com/moov-io/signedxml/commit/204c583e79d4371e5264894222fefea1bb636849"
        },
        "date": 1792410449220,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkEncryptElement",
            "value": 4860,
            "unit": "ns/op\t8600 B/op\t23 allocs/op",
            "extra": "238280 times\n2 procs"
          },
          {
            "name": "BenchmarkEncryptElement - ns/op",
            "value": 4860,
            "unit": "ns/op",
            "extra": "238280 times\n2 procs"
          },
          {
            "name": "BenchmarkEncryptElement - B/op",
            "value": 8600,
            "unit": "B/op",
            "extra": "238280 times\n2 procs"
          },
          {
            "name": "BenchmarkEncryptElement - allocs/op",
            "value": 23,
            "unit": "allocs/op",
            "extra": "238280 times\n2 procs"
          },
          {
            "name": "BenchmarkDecryptElement",
            "value": 15273.5,
            "unit": "ns/op\t10400 B/op\t27 allocs/op",
            "extra": "78560 times\n2 procs"
          },
          {
            "name": "BenchmarkDecryptElement - ns/op",
            "value": 15273.5,
            "unit": "ns/op",
            "extra": "78560 times\n2 procs"
          },
          {
            "name": "BenchmarkDecryptElement - B/op",
            "value": 10400,
            "unit": "B/op",
            "extra": "78560 times\n2 procs"
          },
          {
            "name": "BenchmarkDecryptElement - allocs/op",
            "value": 27,
            "unit": "allocs/op",
            "extra": "78560 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt",
            "value": 181594,
            "unit": "ns/op\t24176 B/op\t118 allocs/op",
            "extra": "6295 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - ns/op",
            "value": 181594,
            "unit": "ns/op",
            "extra": "6295 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - B/op",
            "value": 24176,
            "unit": "B/op",
            "extra": "6295 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - allocs/op",
            "value": 118,
            "unit": "allocs/op",
            "extra": "6295 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement",
            "value": 105618,
            "unit": "ns/op\t1617 B/op\t24 allocs/op",
            "extra": "10000 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - ns/op",
            "value": 105618,
            "unit": "ns/op",
            "extra": "10000 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - B/op",
            "value": 1617,
            "unit": "B/op",
            "extra": "10000 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - allocs/op",
            "value": 24,
            "unit": "allocs/op",
            "extra": "10000 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey",
            "value": 106825,
            "unit": "ns/op\t3296 B/op\t44 allocs/op",
            "extra": "10000 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - ns/op",
            "value": 106825,
            "unit": "ns/op",
            "extra": "10000 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - B/op",
            "value": 3296,
            "unit": "B/op",
            "extra": "10000 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - allocs/op",
            "value": 44,
            "unit": "allocs/op",
            "extra": "10000 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap",
            "value": 1195.5,
            "unit": "ns/op\t736 B/op\t8 allocs/op",
            "extra": "898641 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - ns/op",
            "value": 1195.5,
            "unit": "ns/op",
            "extra": "898641 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - B/op",
            "value": 736,
            "unit": "B/op",
            "extra": "898641 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "898641 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap",
            "value": 1233.5,
            "unit": "ns/op\t720 B/op\t8 allocs/op",
            "extra": "885741 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - ns/op",
            "value": 1233.5,
            "unit": "ns/op",
            "extra": "885741 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - B/op",
            "value": 720,
            "unit": "B/op",
            "extra": "885741 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "885741 times\n2 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt",
            "value": 819.3,
            "unit": "ns/op\t2448 B/op\t4 allocs/op",
            "extra": "1463944 times\n2 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - ns/op",
            "value": 819.3,
            "unit": "ns/op",
            "extra": "1463944 times\n2 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - B/op",
            "value": 2448,
            "unit": "B/op",
            "extra": "1463944 times\n2 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - allocs/op",
            "value": 4,
            "unit": "allocs/op",
            "extra": "1463944 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline",
            "value": 111903.5,
            "unit": "ns/op\t13432 B/op\t117 allocs/op",
            "extra": "10000 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - ns/op",
            "value": 111903.5,
            "unit": "ns/op",
            "extra": "10000 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - B/op",
            "value": 13432,
            "unit": "B/op",
            "extra": "10000 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - allocs/op",
            "value": 117,
            "unit": "allocs/op",
            "extra": "10000 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline",
            "value": 71457,
            "unit": "ns/op\t15176 B/op\t205 allocs/op",
            "extra": "16737 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - ns/op",
            "value": 71457,
            "unit": "ns/op",
            "extra": "16737 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - B/op",
            "value": 15176,
            "unit": "B/op",
            "extra": "16737 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - allocs/op",
            "value": 205,
            "unit": "allocs/op",
            "extra": "16737 times\n2 procs"
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
          "id": "204c583e79d4371e5264894222fefea1bb636849",
          "message": "chore(deps): update github/codeql-action action to v4.39.0 (#151)\n\nCo-authored-by: renovate[bot] <29139614+renovate[bot]@users.noreply.github.com>",
          "timestamp": "2026-10-15T17:00:41Z",
          "url": "https://github.com/moov-io/signedxml/commit/204c583e79d4371e5264894222fefea1bb636849"
        },
        "date": 1792493278516,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkEncryptElement",
            "value": 2689,
            "unit": "ns/op\t8600 B/op\t23 allocs/op",
            "extra": "448089 times\n2 procs"
          },
          {
            "name": "BenchmarkEncryptElement - ns/op",
            "value": 2689,
            "unit": "ns/op",
            "extra": "448089 times\n2 procs"
          },
          {
            "name": "BenchmarkEncryptElement - B/op",
            "value": 8600,
            "unit": "B/op",
            "extra": "448089 times\n2 procs"
          },
          {
            "name": "BenchmarkEncryptElement - allocs/op",
            "value": 23,
            "unit": "allocs/op",
            "extra": "448089 times\n2 procs"
          },
          {
            "name": "BenchmarkDecryptElement",
            "value": 8047.5,
            "unit": "ns/op\t10400 B/op\t27 allocs/op",
            "extra": "150225 times\n2 procs"
          },
          {
            "name": "BenchmarkDecryptElement - ns/op",
            "value": 8047.5,
            "unit": "ns/op",
            "extra": "150225 times\n2 procs"
          },
          {
            "name": "BenchmarkDecryptElement - B/op",
            "value": 10400,
            "unit": "B/op",
            "extra": "150225 times\n2 procs"
          },
          {
            "name": "BenchmarkDecryptElement - allocs/op",
            "value": 27,
            "unit": "allocs/op",
            "extra": "150225 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt",
            "value": 102426,
            "unit": "ns/op\t24176 B/op\t118 allocs/op",
            "extra": "10000 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - ns/op",
            "value": 102426,
            "unit": "ns/op",
            "extra": "10000 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - B/op",
            "value": 24176,
            "unit": "B/op",
            "extra": "10000 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - allocs/op",
            "value": 118,
            "unit": "allocs/op",
            "extra": "10000 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement",
            "value": 61602,
            "unit": "ns/op\t1617 B/op\t24 allocs/op",
            "extra": "19467 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - ns/op",
            "value": 61602,
            "unit": "ns/op",
            "extra": "19467 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - B/op",
            "value": 1617,
            "unit": "B/op",
            "extra": "19467 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - allocs/op",
            "value": 24,
            "unit": "allocs/op",
            "extra": "19467 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey",
            "value": 62106.5,
            "unit": "ns/op\t3296 B/op\t44 allocs/op",
            "extra": "19363 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - ns/op",
            "value": 62106.5,
            "unit": "ns/op",
            "extra": "19363 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - B/op",
            "value": 3296,
            "unit": "B/op",
            "extra": "19363 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - allocs/op",
            "value": 44,
            "unit": "allocs/op",
            "extra": "19363 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap",
            "value": 736.25,
            "unit": "ns/op\t736 B/op\t8 allocs/op",
            "extra": "1623021 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - ns/op",
            "value": 736.25,
            "unit": "ns/op",
            "extra": "1623021 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - B/op",
            "value": 736,
            "unit": "B/op",
            "extra": "1623021 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "1623021 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap",
            "value": 764.3,
            "unit": "ns/op\t720 B/op\t8 allocs/op",
            "extra": "1566807 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - ns/op",
            "value": 764.3,
            "unit": "ns/op",
            "extra": "1566807 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - B/op",
            "value": 720,
            "unit": "B/op",
            "extra": "1566807 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "1566807 times\n2 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt",
            "value": 553.65,
            "unit": "ns/op\t2448 B/op\t4 allocs/op",
            "extra": "2138900 times\n2 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - ns/op",
            "value": 553.65,
            "unit": "ns/op",
            "extra": "2138900 times\n2 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - B/op",
            "value": 2448,
            "unit": "B/op",
            "extra": "2138900 times\n2 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - allocs/op",
            "value": 4,
            "unit": "allocs/op",
            "extra": "2138900 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline",
            "value": 65051,
            "unit": "ns/op\t13432 B/op\t117 allocs/op",
            "extra": "18474 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - ns/op",
            "value": 65051,
            "unit": "ns/op",
            "extra": "18474 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - B/op",
            "value": 13432,
            "unit": "B/op",
            "extra": "18474 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - allocs/op",
            "value": 117,
            "unit": "allocs/op",
            "extra": "18474 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline",
            "value": 40913,
            "unit": "ns/op\t15176 B/op\t205 allocs/op",
            "extra": "29302 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - ns/op",
            "value": 40913,
            "unit": "ns/op",
            "extra": "29302 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - B/op",
            "value": 15176,
            "unit": "B/op",
            "extra": "29302 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - allocs/op",
            "value": 205,
            "unit": "allocs/op",
            "extra": "29302 times\n2 procs"
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
          "id": "77ceb667cecbbb6d4b8decf921906a1426ef9756",
          "message": "chore(deps): update go toolchain directive to v1.27.3 (#152)\n\nCo-authored-by: renovate[bot] <29139614+renovate[bot]@users.noreply.github.com>",
          "timestamp": "2026-10-20T14:46:33Z",
          "url": "https://github.com/moov-io/signedxml/commit/77ceb667cecbbb6d4b8decf921906a1426ef9756"
        },
        "date": 1792580371243,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkEncryptElement",
            "value": 4988.5,
            "unit": "ns/op\t8600 B/op\t23 allocs/op",
            "extra": "239506 times\n2 procs"
          },
          {
            "name": "BenchmarkEncryptElement - ns/op",
            "value": 4988.5,
            "unit": "ns/op",
            "extra": "239506 times\n2 procs"
          },
          {
            "name": "BenchmarkEncryptElement - B/op",
            "value": 8600,
            "unit": "B/op",
            "extra": "239506 times\n2 procs"
          },
          {
            "name": "BenchmarkEncryptElement - allocs/op",
            "value": 23,
            "unit": "allocs/op",
            "extra": "239506 times\n2 procs"
          },
          {
            "name": "BenchmarkDecryptElement",
            "value": 15341.5,
            "unit": "ns/op\t10400 B/op\t27 allocs/op",
            "extra": "78361 times\n2 procs"
          },
          {
            "name": "BenchmarkDecryptElement - ns/op",
            "value": 15341.5,
            "unit": "ns/op",
            "extra": "78361 times\n2 procs"
          },
          {
            "name": "BenchmarkDecryptElement - B/op",
            "value": 10400,
            "unit": "B/op",
            "extra": "78361 times\n2 procs"
          },
          {
            "name": "BenchmarkDecryptElement - allocs/op",
            "value": 27,
            "unit": "allocs/op",
            "extra": "78361 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt",
            "value": 182552.5,
            "unit": "ns/op\t24176 B/op\t118 allocs/op",
            "extra": "6290 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - ns/op",
            "value": 182552.5,
            "unit": "ns/op",
            "extra": "6290 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - B/op",
            "value": 24176,
            "unit": "B/op",
            "extra": "6290 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - allocs/op",
            "value": 118,
            "unit": "allocs/op",
            "extra": "6290 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement",
            "value": 105646.5,
            "unit": "ns/op\t1617 B/op\t24 allocs/op",
            "extra": "10000 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - ns/op",
            "value": 105646.5,
            "unit": "ns/op",
            "extra": "10000 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - B/op",
            "value": 1617,
            "unit": "B/op",
            "extra": "10000 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - allocs/op",
            "value": 24,
            "unit": "allocs/op",
            "extra": "10000 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey",
            "value": 106961.5,
            "unit": "ns/op\t3296 B/op\t44 allocs/op",
            "extra": "10000 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - ns/op",
            "value": 106961.5,
            "unit": "ns/op",
            "extra": "10000 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - B/op",
            "value": 3296,
            "unit": "B/op",
            "extra": "10000 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - allocs/op",
            "value": 44,
            "unit": "allocs/op",
            "extra": "10000 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap",
            "value": 1201,
            "unit": "ns/op\t736 B/op\t8 allocs/op",
            "extra": "944502 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - ns/op",
            "value": 1201,
            "unit": "ns/op",
            "extra": "944502 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - B/op",
            "value": 736,
            "unit": "B/op",
            "extra": "944502 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "944502 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap",
            "value": 1232.5,
            "unit": "ns/op\t720 B/op\t8 allocs/op",
            "extra": "929322 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - ns/op",
            "value": 1232.5,
            "unit": "ns/op",
            "extra": "929322 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - B/op",
            "value": 720,
            "unit": "B/op",
            "extra": "929322 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "929322 times\n2 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt",
            "value": 831.8,
            "unit": "ns/op\t2448 B/op\t4 allocs/op",
            "extra": "1462180 times\n2 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - ns/op",
            "value": 831.8,
            "unit": "ns/op",
            "extra": "1462180 times\n2 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - B/op",
            "value": 2448,
            "unit": "B/op",
            "extra": "1462180 times\n2 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - allocs/op",
            "value": 4,
            "unit": "allocs/op",
            "extra": "1462180 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline",
            "value": 112701,
            "unit": "ns/op\t13432 B/op\t117 allocs/op",
            "extra": "10000 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - ns/op",
            "value": 112701,
            "unit": "ns/op",
            "extra": "10000 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - B/op",
            "value": 13432,
            "unit": "B/op",
            "extra": "10000 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - allocs/op",
            "value": 117,
            "unit": "allocs/op",
            "extra": "10000 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline",
            "value": 71897.5,
            "unit": "ns/op\t15176 B/op\t205 allocs/op",
            "extra": "16656 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - ns/op",
            "value": 71897.5,
            "unit": "ns/op",
            "extra": "16656 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - B/op",
            "value": 15176,
            "unit": "B/op",
            "extra": "16656 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - allocs/op",
            "value": 205,
            "unit": "allocs/op",
            "extra": "16656 times\n2 procs"
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
          "id": "fc7693c6e4d09de90446b2ecc1677cb80e937c0c",
          "message": "chore(deps): update github/codeql-action action to v4.39.1 (#153)\n\nCo-authored-by: renovate[bot] <29139614+renovate[bot]@users.noreply.github.com>",
          "timestamp": "2026-10-21T17:14:50Z",
          "url": "https://github.com/moov-io/signedxml/commit/fc7693c6e4d09de90446b2ecc1677cb80e937c0c"
        },
        "date": 1792666733790,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkEncryptElement",
            "value": 2964.5,
            "unit": "ns/op\t8600 B/op\t23 allocs/op",
            "extra": "391815 times\n2 procs"
          },
          {
            "name": "BenchmarkEncryptElement - ns/op",
            "value": 2964.5,
            "unit": "ns/op",
            "extra": "391815 times\n2 procs"
          },
          {
            "name": "BenchmarkEncryptElement - B/op",
            "value": 8600,
            "unit": "B/op",
            "extra": "391815 times\n2 procs"
          },
          {
            "name": "BenchmarkEncryptElement - allocs/op",
            "value": 23,
            "unit": "allocs/op",
            "extra": "391815 times\n2 procs"
          },
          {
            "name": "BenchmarkDecryptElement",
            "value": 8800,
            "unit": "ns/op\t10400 B/op\t27 allocs/op",
            "extra": "135868 times\n2 procs"
          },
          {
            "name": "BenchmarkDecryptElement - ns/op",
            "value": 8800,
            "unit": "ns/op",
            "extra": "135868 times\n2 procs"
          },
          {
            "name": "BenchmarkDecryptElement - B/op",
            "value": 10400,
            "unit": "B/op",
            "extra": "135868 times\n2 procs"
          },
          {
            "name": "BenchmarkDecryptElement - allocs/op",
            "value": 27,
            "unit": "allocs/op",
            "extra": "135868 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt",
            "value": 107572,
            "unit": "ns/op\t24176 B/op\t118 allocs/op",
            "extra": "10000 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - ns/op",
            "value": 107572,
            "unit": "ns/op",
            "extra": "10000 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - B/op",
            "value": 24176,
            "unit": "B/op",
            "extra": "10000 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - allocs/op",
            "value": 118,
            "unit": "allocs/op",
            "extra": "10000 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement",
            "value": 62468.5,
            "unit": "ns/op\t1617 B/op\t24 allocs/op",
            "extra": "19050 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - ns/op",
            "value": 62468.5,
            "unit": "ns/op",
            "extra": "19050 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - B/op",
            "value": 1617,
            "unit": "B/op",
            "extra": "19050 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - allocs/op",
            "value": 24,
            "unit": "allocs/op",
            "extra": "19050 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey",
            "value": 63770,
            "unit": "ns/op\t3296 B/op\t44 allocs/op",
            "extra": "18915 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - ns/op",
            "value": 63770,
            "unit": "ns/op",
            "extra": "18915 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - B/op",
            "value": 3296,
            "unit": "B/op",
            "extra": "18915 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - allocs/op",
            "value": 44,
            "unit": "allocs/op",
            "extra": "18915 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap",
            "value": 775,
            "unit": "ns/op\t736 B/op\t8 allocs/op",
            "extra": "1558218 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - ns/op",
            "value": 775,
            "unit": "ns/op",
            "extra": "1558218 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - B/op",
            "value": 736,
            "unit": "B/op",
            "extra": "1558218 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "1558218 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap",
            "value": 783.9,
            "unit": "ns/op\t720 B/op\t8 allocs/op",
            "extra": "1525134 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - ns/op",
            "value": 783.9,
            "unit": "ns/op",
            "extra": "1525134 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - B/op",
            "value": 720,
            "unit": "B/op",
            "extra": "1525134 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "1525134 times\n2 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt",
            "value": 593.15,
            "unit": "ns/op\t2448 B/op\t4 allocs/op",
            "extra": "2060923 times\n2 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - ns/op",
            "value": 593.15,
            "unit": "ns/op",
            "extra": "2060923 times\n2 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - B/op",
            "value": 2448,
            "unit": "B/op",
            "extra": "2060923 times\n2 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - allocs/op",
            "value": 4,
            "unit": "allocs/op",
            "extra": "2060923 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline",
            "value": 66688,
            "unit": "ns/op\t13432 B/op\t117 allocs/op",
            "extra": "18144 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - ns/op",
            "value": 66688,
            "unit": "ns/op",
            "extra": "18144 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - B/op",
            "value": 13432,
            "unit": "B/op",
            "extra": "18144 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - allocs/op",
            "value": 117,
            "unit": "allocs/op",
            "extra": "18144 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline",
            "value": 42652.5,
            "unit": "ns/op\t15176 B/op\t205 allocs/op",
            "extra": "28465 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - ns/op",
            "value": 42652.5,
            "unit": "ns/op",
            "extra": "28465 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - B/op",
            "value": 15176,
            "unit": "B/op",
            "extra": "28465 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - allocs/op",
            "value": 205,
            "unit": "allocs/op",
            "extra": "28465 times\n2 procs"
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
          "id": "fc7693c6e4d09de90446b2ecc1677cb80e937c0c",
          "message": "chore(deps): update github/codeql-action action to v4.39.1 (#153)\n\nCo-authored-by: renovate[bot] <29139614+renovate[bot]@users.noreply.github.com>",
          "timestamp": "2026-10-21T17:14:50Z",
          "url": "https://github.com/moov-io/signedxml/commit/fc7693c6e4d09de90446b2ecc1677cb80e937c0c"
        },
        "date": 1792752686898,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkEncryptElement",
            "value": 4171.5,
            "unit": "ns/op\t8600 B/op\t23 allocs/op",
            "extra": "282578 times\n2 procs"
          },
          {
            "name": "BenchmarkEncryptElement - ns/op",
            "value": 4171.5,
            "unit": "ns/op",
            "extra": "282578 times\n2 procs"
          },
          {
            "name": "BenchmarkEncryptElement - B/op",
            "value": 8600,
            "unit": "B/op",
            "extra": "282578 times\n2 procs"
          },
          {
            "name": "BenchmarkEncryptElement - allocs/op",
            "value": 23,
            "unit": "allocs/op",
            "extra": "282578 times\n2 procs"
          },
          {
            "name": "BenchmarkDecryptElement",
            "value": 11616.5,
            "unit": "ns/op\t10400 B/op\t27 allocs/op",
            "extra": "103176 times\n2 procs"
          },
          {
            "name": "BenchmarkDecryptElement - ns/op",
            "value": 11616.5,
            "unit": "ns/op",
            "extra": "103176 times\n2 procs"
          },
          {
            "name": "BenchmarkDecryptElement - B/op",
            "value": 10400,
            "unit": "B/op",
            "extra": "103176 times\n2 procs"
          },
          {
            "name": "BenchmarkDecryptElement - allocs/op",
            "value": 27,
            "unit": "allocs/op",
            "extra": "103176 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt",
            "value": 154598,
            "unit": "ns/op\t24176 B/op\t118 allocs/op",
            "extra": "7399 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - ns/op",
            "value": 154598,
            "unit": "ns/op",
            "extra": "7399 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - B/op",
            "value": 24176,
            "unit": "B/op",
            "extra": "7399 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - allocs/op",
            "value": 118,
            "unit": "allocs/op",
            "extra": "7399 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement",
            "value": 89961.5,
            "unit": "ns/op\t1617 B/op\t24 allocs/op",
            "extra": "13326 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - ns/op",
            "value": 89961.5,
            "unit": "ns/op",
            "extra": "13326 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - B/op",
            "value": 1617,
            "unit": "B/op",
            "extra": "13326 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - allocs/op",
            "value": 24,
            "unit": "allocs/op",
            "extra": "13326 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey",
            "value": 91059.5,
            "unit": "ns/op\t3296 B/op\t44 allocs/op",
            "extra": "13168 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - ns/op",
            "value": 91059.5,
            "unit": "ns/op",
            "extra": "13168 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - B/op",
            "value": 3296,
            "unit": "B/op",
            "extra": "13168 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - allocs/op",
            "value": 44,
            "unit": "allocs/op",
            "extra": "13168 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap",
            "value": 953.9,
            "unit": "ns/op\t736 B/op\t8 allocs/op",
            "extra": "1258087 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - ns/op",
            "value": 953.9,
            "unit": "ns/op",
            "extra": "1258087 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - B/op",
            "value": 736,
            "unit": "B/op",
            "extra": "1258087 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "1258087 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap",
            "value": 1012,
            "unit": "ns/op\t720 B/op\t8 allocs/op",
            "extra": "1234688 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - ns/op",
            "value": 1012,
            "unit": "ns/op",
            "extra": "1234688 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - B/op",
            "value": 720,
            "unit": "B/op",
            "extra": "1234688 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "1234688 times\n2 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt",
            "value": 739.35,
            "unit": "ns/op\t2448 B/op\t4 allocs/op",
            "extra": "1702318 times\n2 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - ns/op",
            "value": 739.35,
            "unit": "ns/op",
            "extra": "1702318 times\n2 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - B/op",
            "value": 2448,
            "unit": "B/op",
            "extra": "1702318 times\n2 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - allocs/op",
            "value": 4,
            "unit": "allocs/op",
            "extra": "1702318 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline",
            "value": 100175.5,
            "unit": "ns/op\t13432 B/op\t117 allocs/op",
            "extra": "12000 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - ns/op",
            "value": 100175.5,
            "unit": "ns/op",
            "extra": "12000 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - B/op",
            "value": 13432,
            "unit": "B/op",
            "extra": "12000 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - allocs/op",
            "value": 117,
            "unit": "allocs/op",
            "extra": "12000 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline",
            "value": 61287.5,
            "unit": "ns/op\t15176 B/op\t205 allocs/op",
            "extra": "19406 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - ns/op",
            "value": 61287.5,
            "unit": "ns/op",
            "extra": "19406 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - B/op",
            "value": 15176,
            "unit": "B/op",
            "extra": "19406 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - allocs/op",
            "value": 205,
            "unit": "allocs/op",
            "extra": "19406 times\n2 procs"
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
          "id": "fc7693c6e4d09de90446b2ecc1677cb80e937c0c",
          "message": "chore(deps): update github/codeql-action action to v4.39.1 (#153)\n\nCo-authored-by: renovate[bot] <29139614+renovate[bot]@users.noreply.github.com>",
          "timestamp": "2026-10-21T17:14:50Z",
          "url": "https://github.com/moov-io/signedxml/commit/fc7693c6e4d09de90446b2ecc1677cb80e937c0c"
        },
        "date": 1792836399007,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkEncryptElement",
            "value": 4178.5,
            "unit": "ns/op\t8600 B/op\t23 allocs/op",
            "extra": "282954 times\n2 procs"
          },
          {
            "name": "BenchmarkEncryptElement - ns/op",
            "value": 4178.5,
            "unit": "ns/op",
            "extra": "282954 times\n2 procs"
          },
          {
            "name": "BenchmarkEncryptElement - B/op",
            "value": 8600,
            "unit": "B/op",
            "extra": "282954 times\n2 procs"
          },
          {
            "name": "BenchmarkEncryptElement - allocs/op",
            "value": 23,
            "unit": "allocs/op",
            "extra": "282954 times\n2 procs"
          },
          {
            "name": "BenchmarkDecryptElement",
            "value": 11607,
            "unit": "ns/op\t10400 B/op\t27 allocs/op",
            "extra": "103490 times\n2 procs"
          },
          {
            "name": "BenchmarkDecryptElement - ns/op",
            "value": 11607,
            "unit": "ns/op",
            "extra": "103490 times\n2 procs"
          },
          {
            "name": "BenchmarkDecryptElement - B/op",
            "value": 10400,
            "unit": "B/op",
            "extra": "103490 times\n2 procs"
          },
          {
            "name": "BenchmarkDecryptElement - allocs/op",
            "value": 27,
            "unit": "allocs/op",
            "extra": "103490 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt",
            "value": 154627,
            "unit": "ns/op\t24176 B/op\t118 allocs/op",
            "extra": "7416 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - ns/op",
            "value": 154627,
            "unit": "ns/op",
            "extra": "7416 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - B/op",
            "value": 24176,
            "unit": "B/op",
            "extra": "7416 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - allocs/op",
            "value": 118,
            "unit": "allocs/op",
            "extra": "7416 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement",
            "value": 89984,
            "unit": "ns/op\t1617 B/op\t24 allocs/op",
            "extra": "13328 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - ns/op",
            "value": 89984,
            "unit": "ns/op",
            "extra": "13328 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - B/op",
            "value": 1617,
            "unit": "B/op",
            "extra": "13328 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - allocs/op",
            "value": 24,
            "unit": "allocs/op",
            "extra": "13328 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey",
            "value": 91056,
            "unit": "ns/op\t3296 B/op\t44 allocs/op",
            "extra": "13161 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - ns/op",
            "value": 91056,
            "unit": "ns/op",
            "extra": "13161 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - B/op",
            "value": 3296,
            "unit": "B/op",
            "extra": "13161 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - allocs/op",
            "value": 44,
            "unit": "allocs/op",
            "extra": "13161 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap",
            "value": 956.85,
            "unit": "ns/op\t736 B/op\t8 allocs/op",
            "extra": "1252600 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - ns/op",
            "value": 956.85,
            "unit": "ns/op",
            "extra": "1252600 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - B/op",
            "value": 736,
            "unit": "B/op",
            "extra": "1252600 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "1252600 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap",
            "value": 970.5,
            "unit": "ns/op\t720 B/op\t8 allocs/op",
            "extra": "1235647 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - ns/op",
            "value": 970.5,
            "unit": "ns/op",
            "extra": "1235647 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - B/op",
            "value": 720,
            "unit": "B/op",
            "extra": "1235647 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "1235647 times\n2 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt",
            "value": 666.7,
            "unit": "ns/op\t2448 B/op\t4 allocs/op",
            "extra": "1795585 times\n2 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - ns/op",
            "value": 666.7,
            "unit": "ns/op",
            "extra": "1795585 times\n2 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - B/op",
            "value": 2448,
            "unit": "B/op",
            "extra": "1795585 times\n2 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - allocs/op",
            "value": 4,
            "unit": "allocs/op",
            "extra": "1795585 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline",
            "value": 95571.5,
            "unit": "ns/op\t13432 B/op\t117 allocs/op",
            "extra": "12548 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - ns/op",
            "value": 95571.5,
            "unit": "ns/op",
            "extra": "12548 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - B/op",
            "value": 13432,
            "unit": "B/op",
            "extra": "12548 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - allocs/op",
            "value": 117,
            "unit": "allocs/op",
            "extra": "12548 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline",
            "value": 59081,
            "unit": "ns/op\t15176 B/op\t205 allocs/op",
            "extra": "20314 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - ns/op",
            "value": 59081,
            "unit": "ns/op",
            "extra": "20314 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - B/op",
            "value": 15176,
            "unit": "B/op",
            "extra": "20314 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - allocs/op",
            "value": 205,
            "unit": "allocs/op",
            "extra": "20314 times\n2 procs"
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
          "id": "fc7693c6e4d09de90446b2ecc1677cb80e937c0c",
          "message": "chore(deps): update github/codeql-action action to v4.39.1 (#153)\n\nCo-authored-by: renovate[bot] <29139614+renovate[bot]@users.noreply.github.com>",
          "timestamp": "2026-10-21T17:14:50Z",
          "url": "https://github.com/moov-io/signedxml/commit/fc7693c6e4d09de90446b2ecc1677cb80e937c0c"
        },
        "date": 1792924305478,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkEncryptElement",
            "value": 2850.5,
            "unit": "ns/op\t8600 B/op\t23 allocs/op",
            "extra": "412983 times\n2 procs"
          },
          {
            "name": "BenchmarkEncryptElement - ns/op",
            "value": 2850.5,
            "unit": "ns/op",
            "extra": "412983 times\n2 procs"
          },
          {
            "name": "BenchmarkEncryptElement - B/op",
            "value": 8600,
            "unit": "B/op",
            "extra": "412983 times\n2 procs"
          },
          {
            "name": "BenchmarkEncryptElement - allocs/op",
            "value": 23,
            "unit": "allocs/op",
            "extra": "412983 times\n2 procs"
          },
          {
            "name": "BenchmarkDecryptElement",
            "value": 8732,
            "unit": "ns/op\t10400 B/op\t27 allocs/op",
            "extra": "139956 times\n2 procs"
          },
          {
            "name": "BenchmarkDecryptElement - ns/op",
            "value": 8732,
            "unit": "ns/op",
            "extra": "139956 times\n2 procs"
          },
          {
            "name": "BenchmarkDecryptElement - B/op",
            "value": 10400,
            "unit": "B/op",
            "extra": "139956 times\n2 procs"
          },
          {
            "name": "BenchmarkDecryptElement - allocs/op",
            "value": 27,
            "unit": "allocs/op",
            "extra": "139956 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt",
            "value": 108698,
            "unit": "ns/op\t24176 B/op\t118 allocs/op",
            "extra": "10000 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - ns/op",
            "value": 108698,
            "unit": "ns/op",
            "extra": "10000 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - B/op",
            "value": 24176,
            "unit": "B/op",
            "extra": "10000 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - allocs/op",
            "value": 118,
            "unit": "allocs/op",
            "extra": "10000 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement",
            "value": 62987.5,
            "unit": "ns/op\t1617 B/op\t24 allocs/op",
            "extra": "19065 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - ns/op",
            "value": 62987.5,
            "unit": "ns/op",
            "extra": "19065 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - B/op",
            "value": 1617,
            "unit": "B/op",
            "extra": "19065 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - allocs/op",
            "value": 24,
            "unit": "allocs/op",
            "extra": "19065 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey",
            "value": 64001.5,
            "unit": "ns/op\t3296 B/op\t44 allocs/op",
            "extra": "18932 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - ns/op",
            "value": 64001.5,
            "unit": "ns/op",
            "extra": "18932 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - B/op",
            "value": 3296,
            "unit": "B/op",
            "extra": "18932 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - allocs/op",
            "value": 44,
            "unit": "allocs/op",
            "extra": "18932 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap",
            "value": 768.55,
            "unit": "ns/op\t736 B/op\t8 allocs/op",
            "extra": "1567153 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - ns/op",
            "value": 768.55,
            "unit": "ns/op",
            "extra": "1567153 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - B/op",
            "value": 736,
            "unit": "B/op",
            "extra": "1567153 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "1567153 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap",
            "value": 776.05,
            "unit": "ns/op\t720 B/op\t8 allocs/op",
            "extra": "1545787 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - ns/op",
            "value": 776.05,
            "unit": "ns/op",
            "extra": "1545787 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - B/op",
            "value": 720,
            "unit": "B/op",
            "extra": "1545787 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "1545787 times\n2 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt",
            "value": 550.45,
            "unit": "ns/op\t2448 B/op\t4 allocs/op",
            "extra": "2160200 times\n2 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - ns/op",
            "value": 550.45,
            "unit": "ns/op",
            "extra": "2160200 times\n2 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - B/op",
            "value": 2448,
            "unit": "B/op",
            "extra": "2160200 times\n2 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - allocs/op",
            "value": 4,
            "unit": "allocs/op",
            "extra": "2160200 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline",
            "value": 67016,
            "unit": "ns/op\t13432 B/op\t117 allocs/op",
            "extra": "18051 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - ns/op",
            "value": 67016,
            "unit": "ns/op",
            "extra": "18051 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - B/op",
            "value": 13432,
            "unit": "B/op",
            "extra": "18051 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - allocs/op",
            "value": 117,
            "unit": "allocs/op",
            "extra": "18051 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline",
            "value": 41945.5,
            "unit": "ns/op\t15176 B/op\t205 allocs/op",
            "extra": "28609 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - ns/op",
            "value": 41945.5,
            "unit": "ns/op",
            "extra": "28609 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - B/op",
            "value": 15176,
            "unit": "B/op",
            "extra": "28609 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - allocs/op",
            "value": 205,
            "unit": "allocs/op",
            "extra": "28609 times\n2 procs"
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
          "id": "fc7693c6e4d09de90446b2ecc1677cb80e937c0c",
          "message": "chore(deps): update github/codeql-action action to v4.39.1 (#153)\n\nCo-authored-by: renovate[bot] <29139614+renovate[bot]@users.noreply.github.com>",
          "timestamp": "2026-10-21T17:14:50Z",
          "url": "https://github.com/moov-io/signedxml/commit/fc7693c6e4d09de90446b2ecc1677cb80e937c0c"
        },
        "date": 1793016237055,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkEncryptElement",
            "value": 2702.5,
            "unit": "ns/op\t8600 B/op\t23 allocs/op",
            "extra": "446386 times\n2 procs"
          },
          {
            "name": "BenchmarkEncryptElement - ns/op",
            "value": 2702.5,
            "unit": "ns/op",
            "extra": "446386 times\n2 procs"
          },
          {
            "name": "BenchmarkEncryptElement - B/op",
            "value": 8600,
            "unit": "B/op",
            "extra": "446386 times\n2 procs"
          },
          {
            "name": "BenchmarkEncryptElement - allocs/op",
            "value": 23,
            "unit": "allocs/op",
            "extra": "446386 times\n2 procs"
          },
          {
            "name": "BenchmarkDecryptElement",
            "value": 8123,
            "unit": "ns/op\t10400 B/op\t27 allocs/op",
            "extra": "150476 times\n2 procs"
          },
          {
            "name": "BenchmarkDecryptElement - ns/op",
            "value": 8123,
            "unit": "ns/op",
            "extra": "150476 times\n2 procs"
          },
          {
            "name": "BenchmarkDecryptElement - B/op",
            "value": 10400,
            "unit": "B/op",
            "extra": "150476 times\n2 procs"
          },
          {
            "name": "BenchmarkDecryptElement - allocs/op",
            "value": 27,
            "unit": "allocs/op",
            "extra": "150476 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt",
            "value": 101670,
            "unit": "ns/op\t24176 B/op\t118 allocs/op",
            "extra": "10000 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - ns/op",
            "value": 101670,
            "unit": "ns/op",
            "extra": "10000 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - B/op",
            "value": 24176,
            "unit": "B/op",
            "extra": "10000 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - allocs/op",
            "value": 118,
            "unit": "allocs/op",
            "extra": "10000 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement",
            "value": 59467,
            "unit": "ns/op\t1617 B/op\t24 allocs/op",
            "extra": "20251 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - ns/op",
            "value": 59467,
            "unit": "ns/op",
            "extra": "20251 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - B/op",
            "value": 1617,
            "unit": "B/op",
            "extra": "20251 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - allocs/op",
            "value": 24,
            "unit": "allocs/op",
            "extra": "20251 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey",
            "value": 60655.5,
            "unit": "ns/op\t3296 B/op\t44 allocs/op",
            "extra": "19647 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - ns/op",
            "value": 60655.5,
            "unit": "ns/op",
            "extra": "19647 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - B/op",
            "value": 3296,
            "unit": "B/op",
            "extra": "19647 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - allocs/op",
            "value": 44,
            "unit": "allocs/op",
            "extra": "19647 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap",
            "value": 721.2,
            "unit": "ns/op\t736 B/op\t8 allocs/op",
            "extra": "1670584 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - ns/op",
            "value": 721.2,
            "unit": "ns/op",
            "extra": "1670584 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - B/op",
            "value": 736,
            "unit": "B/op",
            "extra": "1670584 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "1670584 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap",
            "value": 735.4,
            "unit": "ns/op\t720 B/op\t8 allocs/op",
            "extra": "1645532 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - ns/op",
            "value": 735.4,
            "unit": "ns/op",
            "extra": "1645532 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - B/op",
            "value": 720,
            "unit": "B/op",
            "extra": "1645532 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "1645532 times\n2 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt",
            "value": 550.7,
            "unit": "ns/op\t2448 B/op\t4 allocs/op",
            "extra": "2203032 times\n2 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - ns/op",
            "value": 550.7,
            "unit": "ns/op",
            "extra": "2203032 times\n2 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - B/op",
            "value": 2448,
            "unit": "B/op",
            "extra": "2203032 times\n2 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - allocs/op",
            "value": 4,
            "unit": "allocs/op",
            "extra": "2203032 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline",
            "value": 61784.5,
            "unit": "ns/op\t13432 B/op\t117 allocs/op",
            "extra": "19245 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - ns/op",
            "value": 61784.5,
            "unit": "ns/op",
            "extra": "19245 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - B/op",
            "value": 13432,
            "unit": "B/op",
            "extra": "19245 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - allocs/op",
            "value": 117,
            "unit": "allocs/op",
            "extra": "19245 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline",
            "value": 39539.5,
            "unit": "ns/op\t15176 B/op\t205 allocs/op",
            "extra": "30549 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - ns/op",
            "value": 39539.5,
            "unit": "ns/op",
            "extra": "30549 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - B/op",
            "value": 15176,
            "unit": "B/op",
            "extra": "30549 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - allocs/op",
            "value": 205,
            "unit": "allocs/op",
            "extra": "30549 times\n2 procs"
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
          "id": "fbadacf0cd4560762922b2e2e154b3208caae191",
          "message": "fix: bound InclusiveNamespaces PrefixList during exclusive c14n (#156)\n\nv1.4.1 capped in-scope xmlns maps but still split PrefixList without a\nlimit and walked every token at every element. Scan the attribute in\nplace, cap unique prefixes at 8192, and intersect the set with in-scope\nnamespaces so cost follows the existing namespace bound.\n\nReported-by: Naor Yaacov",
          "timestamp": "2026-10-26T20:04:39Z",
          "url": "https://github.com/moov-io/signedxml/commit/fbadacf0cd4560762922b2e2e154b3208caae191"
        },
        "date": 1793100247529,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkEncryptElement",
            "value": 4223.5,
            "unit": "ns/op\t8600 B/op\t23 allocs/op",
            "extra": "279132 times\n2 procs"
          },
          {
            "name": "BenchmarkEncryptElement - ns/op",
            "value": 4223.5,
            "unit": "ns/op",
            "extra": "279132 times\n2 procs"
          },
          {
            "name": "BenchmarkEncryptElement - B/op",
            "value": 8600,
            "unit": "B/op",
            "extra": "279132 times\n2 procs"
          },
          {
            "name": "BenchmarkEncryptElement - allocs/op",
            "value": 23,
            "unit": "allocs/op",
            "extra": "279132 times\n2 procs"
          },
          {
            "name": "BenchmarkDecryptElement",
            "value": 11736,
            "unit": "ns/op\t10400 B/op\t27 allocs/op",
            "extra": "100404 times\n2 procs"
          },
          {
            "name": "BenchmarkDecryptElement - ns/op",
            "value": 11736,
            "unit": "ns/op",
            "extra": "100404 times\n2 procs"
          },
          {
            "name": "BenchmarkDecryptElement - B/op",
            "value": 10400,
            "unit": "B/op",
            "extra": "100404 times\n2 procs"
          },
          {
            "name": "BenchmarkDecryptElement - allocs/op",
            "value": 27,
            "unit": "allocs/op",
            "extra": "100404 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt",
            "value": 156378.5,
            "unit": "ns/op\t24176 B/op\t118 allocs/op",
            "extra": "7280 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - ns/op",
            "value": 156378.5,
            "unit": "ns/op",
            "extra": "7280 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - B/op",
            "value": 24176,
            "unit": "B/op",
            "extra": "7280 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - allocs/op",
            "value": 118,
            "unit": "allocs/op",
            "extra": "7280 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement",
            "value": 90134,
            "unit": "ns/op\t1617 B/op\t24 allocs/op",
            "extra": "13322 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - ns/op",
            "value": 90134,
            "unit": "ns/op",
            "extra": "13322 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - B/op",
            "value": 1617,
            "unit": "B/op",
            "extra": "13322 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - allocs/op",
            "value": 24,
            "unit": "allocs/op",
            "extra": "13322 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey",
            "value": 91402.5,
            "unit": "ns/op\t3296 B/op\t44 allocs/op",
            "extra": "13131 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - ns/op",
            "value": 91402.5,
            "unit": "ns/op",
            "extra": "13131 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - B/op",
            "value": 3296,
            "unit": "B/op",
            "extra": "13131 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - allocs/op",
            "value": 44,
            "unit": "allocs/op",
            "extra": "13131 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap",
            "value": 964.7,
            "unit": "ns/op\t736 B/op\t8 allocs/op",
            "extra": "1247594 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - ns/op",
            "value": 964.7,
            "unit": "ns/op",
            "extra": "1247594 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - B/op",
            "value": 736,
            "unit": "B/op",
            "extra": "1247594 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "1247594 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap",
            "value": 976,
            "unit": "ns/op\t720 B/op\t8 allocs/op",
            "extra": "1230518 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - ns/op",
            "value": 976,
            "unit": "ns/op",
            "extra": "1230518 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - B/op",
            "value": 720,
            "unit": "B/op",
            "extra": "1230518 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "1230518 times\n2 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt",
            "value": 677.4,
            "unit": "ns/op\t2448 B/op\t4 allocs/op",
            "extra": "1794555 times\n2 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - ns/op",
            "value": 677.4,
            "unit": "ns/op",
            "extra": "1794555 times\n2 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - B/op",
            "value": 2448,
            "unit": "B/op",
            "extra": "1794555 times\n2 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - allocs/op",
            "value": 4,
            "unit": "allocs/op",
            "extra": "1794555 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline",
            "value": 96855,
            "unit": "ns/op\t13432 B/op\t117 allocs/op",
            "extra": "12402 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - ns/op",
            "value": 96855,
            "unit": "ns/op",
            "extra": "12402 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - B/op",
            "value": 13432,
            "unit": "B/op",
            "extra": "12402 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - allocs/op",
            "value": 117,
            "unit": "allocs/op",
            "extra": "12402 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline",
            "value": 60003,
            "unit": "ns/op\t15176 B/op\t205 allocs/op",
            "extra": "19981 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - ns/op",
            "value": 60003,
            "unit": "ns/op",
            "extra": "19981 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - B/op",
            "value": 15176,
            "unit": "B/op",
            "extra": "19981 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - allocs/op",
            "value": 205,
            "unit": "allocs/op",
            "extra": "19981 times\n2 procs"
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
          "id": "fbadacf0cd4560762922b2e2e154b3208caae191",
          "message": "fix: bound InclusiveNamespaces PrefixList during exclusive c14n (#156)\n\nv1.4.1 capped in-scope xmlns maps but still split PrefixList without a\nlimit and walked every token at every element. Scan the attribute in\nplace, cap unique prefixes at 8192, and intersect the set with in-scope\nnamespaces so cost follows the existing namespace bound.\n\nReported-by: Naor Yaacov",
          "timestamp": "2026-10-26T20:04:39Z",
          "url": "https://github.com/moov-io/signedxml/commit/fbadacf0cd4560762922b2e2e154b3208caae191"
        },
        "date": 1793188655912,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkEncryptElement",
            "value": 4105,
            "unit": "ns/op\t8600 B/op\t23 allocs/op",
            "extra": "287401 times\n2 procs"
          },
          {
            "name": "BenchmarkEncryptElement - ns/op",
            "value": 4105,
            "unit": "ns/op",
            "extra": "287401 times\n2 procs"
          },
          {
            "name": "BenchmarkEncryptElement - B/op",
            "value": 8600,
            "unit": "B/op",
            "extra": "287401 times\n2 procs"
          },
          {
            "name": "BenchmarkEncryptElement - allocs/op",
            "value": 23,
            "unit": "allocs/op",
            "extra": "287401 times\n2 procs"
          },
          {
            "name": "BenchmarkDecryptElement",
            "value": 11533,
            "unit": "ns/op\t10400 B/op\t27 allocs/op",
            "extra": "102986 times\n2 procs"
          },
          {
            "name": "BenchmarkDecryptElement - ns/op",
            "value": 11533,
            "unit": "ns/op",
            "extra": "102986 times\n2 procs"
          },
          {
            "name": "BenchmarkDecryptElement - B/op",
            "value": 10400,
            "unit": "B/op",
            "extra": "102986 times\n2 procs"
          },
          {
            "name": "BenchmarkDecryptElement - allocs/op",
            "value": 27,
            "unit": "allocs/op",
            "extra": "102986 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt",
            "value": 155986.5,
            "unit": "ns/op\t24176 B/op\t118 allocs/op",
            "extra": "7363 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - ns/op",
            "value": 155986.5,
            "unit": "ns/op",
            "extra": "7363 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - B/op",
            "value": 24176,
            "unit": "B/op",
            "extra": "7363 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519EncryptDecrypt - allocs/op",
            "value": 118,
            "unit": "allocs/op",
            "extra": "7363 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement",
            "value": 89952.5,
            "unit": "ns/op\t1617 B/op\t24 allocs/op",
            "extra": "13323 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - ns/op",
            "value": 89952.5,
            "unit": "ns/op",
            "extra": "13323 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - B/op",
            "value": 1617,
            "unit": "B/op",
            "extra": "13323 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519KeyAgreement - allocs/op",
            "value": 24,
            "unit": "allocs/op",
            "extra": "13323 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey",
            "value": 91370.5,
            "unit": "ns/op\t3296 B/op\t44 allocs/op",
            "extra": "13125 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - ns/op",
            "value": 91370.5,
            "unit": "ns/op",
            "extra": "13125 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - B/op",
            "value": 3296,
            "unit": "B/op",
            "extra": "13125 times\n2 procs"
          },
          {
            "name": "BenchmarkX25519WrapKey - allocs/op",
            "value": 44,
            "unit": "allocs/op",
            "extra": "13125 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap",
            "value": 961.9,
            "unit": "ns/op\t736 B/op\t8 allocs/op",
            "extra": "1249080 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - ns/op",
            "value": 961.9,
            "unit": "ns/op",
            "extra": "1249080 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - B/op",
            "value": 736,
            "unit": "B/op",
            "extra": "1249080 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyWrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "1249080 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap",
            "value": 971.15,
            "unit": "ns/op\t720 B/op\t8 allocs/op",
            "extra": "1235916 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - ns/op",
            "value": 971.15,
            "unit": "ns/op",
            "extra": "1235916 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - B/op",
            "value": 720,
            "unit": "B/op",
            "extra": "1235916 times\n2 procs"
          },
          {
            "name": "BenchmarkAESKeyUnwrap - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "1235916 times\n2 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt",
            "value": 650.75,
            "unit": "ns/op\t2448 B/op\t4 allocs/op",
            "extra": "1815873 times\n2 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - ns/op",
            "value": 650.75,
            "unit": "ns/op",
            "extra": "1815873 times\n2 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - B/op",
            "value": 2448,
            "unit": "B/op",
            "extra": "1815873 times\n2 procs"
          },
          {
            "name": "BenchmarkAESGCMEncrypt - allocs/op",
            "value": 4,
            "unit": "allocs/op",
            "extra": "1815873 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline",
            "value": 95901.5,
            "unit": "ns/op\t13432 B/op\t117 allocs/op",
            "extra": "12507 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - ns/op",
            "value": 95901.5,
            "unit": "ns/op",
            "extra": "12507 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - B/op",
            "value": 13432,
            "unit": "B/op",
            "extra": "12507 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullEncryptionPipeline - allocs/op",
            "value": 117,
            "unit": "allocs/op",
            "extra": "12507 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline",
            "value": 59161.5,
            "unit": "ns/op\t15176 B/op\t205 allocs/op",
            "extra": "20124 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - ns/op",
            "value": 59161.5,
            "unit": "ns/op",
            "extra": "20124 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - B/op",
            "value": 15176,
            "unit": "B/op",
            "extra": "20124 times\n2 procs"
          },
          {
            "name": "BenchmarkW3CFullDecryptionPipeline - allocs/op",
            "value": 205,
            "unit": "allocs/op",
            "extra": "20124 times\n2 procs"
          }
        ]
      }
    ]
  }
}
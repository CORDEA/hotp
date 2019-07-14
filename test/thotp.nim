# Copyright 2019 Yoshihiro Tanaka
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

  # http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Author: Yoshihiro Tanaka <contact@cordea.jp>
# date  : 2019-07-14

import unittest
import ../src/hotp

suite "HOTP test":
  setup:
    const
      secretSha1 = "01234567890123456789"
      secretSha256 = "01234567890123456789012345678901"
      secretSha512 = "0123456789012345678901234567890123456789012345678901234567890123"

  test "Sha1 test":
    check(generate(secretSha1, 0, 6, TypeSha1) == "181618")
    check(generate(secretSha1, 0, 7, TypeSha1) == "6181618")
    check(generate(secretSha1, 0, 8, TypeSha1) == "46181618")

    check(generate(secretSha1, 1, 6, TypeSha1) == "298391")
    check(generate(secretSha1, 1, 7, TypeSha1) == "8298391")
    check(generate(secretSha1, 1, 8, TypeSha1) == "08298391")

    check(generate(secretSha1, 2, 6, TypeSha1) == "812177")
    check(generate(secretSha1, 2, 7, TypeSha1) == "8812177")
    check(generate(secretSha1, 2, 8, TypeSha1) == "28812177")

    check(generate(secretSha1, 3, 6, TypeSha1) == "184071")
    check(generate(secretSha1, 3, 7, TypeSha1) == "5184071")
    check(generate(secretSha1, 3, 8, TypeSha1) == "05184071")

  test "Sha256 test":
    check(generate(secretSha256, 0, 8, TypeSha256) == "73295427")

    check(generate(secretSha256, 1, 8, TypeSha256) == "24484092")

    check(generate(secretSha256, 2, 8, TypeSha256) == "31148427")

    check(generate(secretSha256, 3, 8, TypeSha256) == "35884348")

  test "Sha512 test":
    check(generate(secretSha512, 0, 8, TypeSha512) == "88294024")

    check(generate(secretSha512, 1, 8, TypeSha512) == "79053995")

    check(generate(secretSha512, 2, 8, TypeSha512) == "20393837")

    check(generate(secretSha512, 3, 8, TypeSha512) == "00249086")

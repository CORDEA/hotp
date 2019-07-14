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
# date  : 2019-07-13

import hmac
import sequtils

type
  UnsupportedDigitLengthError = object of Exception

  HashFunctionType* = enum
    TypeSha1, TypeSha256, TypeSha512

  Hotp* = ref object
    secret: string
    digits: int
    hashType: HashFunctionType

proc newHotp*(secret: string, digits: int, hashType: HashFunctionType): Hotp =
  result = Hotp(
    secret: secret,
    digits: digits,
    hashType: hashType
  )

proc calculateHmac(secret, text: string, hashType: HashFunctionType): seq[int] =
  case hashType
  of TypeSha1:
    result = hmac_sha1(secret, text).toSeq().mapIt(int(it))
  of TypeSha256:
    result = hmac_sha256(secret, text).toSeq().mapIt(int(it))
  of TypeSha512:
    result = hmac_sha512(secret, text).toSeq().mapIt(int(it))

proc generate*(secret: string, movingFactor: int, digits: int, hashType: HashFunctionType): string =
  var factor = movingFactor
  var text = ""
  for i in 0..7:
    text = char(byte(factor and 0xff)) & text
    factor = factor shr 8

  let hmac = calculateHmac(secret, text, hashType)
  let offset = hmac[len(hmac)-1] and 0xf
  let binary =
    (int(hmac[offset] and 0x7f) shl 24) or
      (int(hmac[offset+1] and 0xff) shl 16) or
      (int(hmac[offset+2] and 0xff) shl 8) or
      int(hmac[offset+3] and 0xff)
  var otp = 0
  case digits
  of 6:
    otp = binary mod 1000000
  of 7:
    otp = binary mod 10000000
  of 8:
    otp = binary mod 100000000
  else:
    discard

  if otp == 0:
    raise newException(UnsupportedDigitLengthError, "Unsupported number of digits.")

  result = $otp
  while len(result) < digits:
    result = "0" & result

proc generate*(hotp: Hotp, movingFactor: int): string =
  result = generate(hotp.secret, movingFactor, hotp.digits, hotp.hashType)

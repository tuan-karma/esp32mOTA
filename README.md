# esp32mOTA library for Arduino

## Purpose

A simple library to add support for Over-The-Air (OTA) firmware updates for your project with digital signature verification.

## Features

Minimify/Improve the code --> elegant and performance. Concentrating on two features: 
- [x] Security: Digital signature verification with public key embedded into firmware and updatable. 
- [x] Peformance: Eliminate unneccessary functions, minimize the use of String objects, refactorize the codes. 
- [x] DeviceID in the get request for server's loging purpose 

## Todos
- [x] Test: Using a github repo as the https server for the firmwares.
- [ ] Improve code: log_level 4 --> log_d 
- [ ] Secure OTA config solution: Develop dynamically OTA config scheme with signature check for esp32 --> store key value in NVS partition.



## How it works

This library tries to access a JSON file hosted on a webserver, and reviews it to decide if a newer firmware has been published, if so it will download it and install it.

There are a few things that need to be in place for an update to work.

- A webserver with the firmware information in a JSON file
- Firmware version
- Firmware type
- Firmware bin
- **For https or signature check**: This library deliberately doesn't rely on root_ca.pem (https) for security because it makes us depending on a third party authority (What happends in the expried moment of the certificate?). We should rely on the signature check using rsa_key.pem instead. Using rsa key signature check provides an equivalent security strength as https CA (they use the same method). Using rsa key signature check, we can manage our security procedure, for example: we can establish a authorization procedure of personel who have authority to sign the devices' firmwares; we can manage the personel transistion in the futures as well as how the key is expired. 

You can supply http or https URLs to the checkURL. If you are using https, it will establish a TLS connection without CA check (aka. `client.setInsecure()`). For the actual firmware it will use https when you define port 443 or 4433. Otherwise it will use plain http.

## Usage

### Hosted JSON

This is hosted by a webserver and contains information about the latest firmware:

```json
{
    "type": "esp32-fota-http",
    "version": 2,
    "host": "192.168.0.100",
    "port": 80,
    "bin": "/fota/esp32-fota-http-2.bin"
}
```

Version information can be either a single number or a semantic version string. Alternatively, a full URL path can be provided:

```json
{
    "type": "esp32-fota-http",
    "version": "2.5.1",
    "url": "http://192.168.0.100/fota/esp32-fota-http-2.bin"
}
```

A single JSON file can provide information on multiple firmware types by combining them together into an array. When this is loaded, the firmware manifest with a type matching the one passed to the esp32FOTA constructor will be selected:

```json
[
   {
      "type":"esp32-fota-http",
      "version":"0.0.2",
      "url":"http://192.168.0.100/fota/esp32-fota-http-2.bin"
   },
   {
      "type":"esp32-other-hardware",
      "version":"0.0.3",
      "url":"http://192.168.0.100/fota/esp32-other-hardware.bin"
   }
]
```


#### Firmware types

Types are used to compare with the current loaded firmware, this is used to make sure that when loaded, the device will still do the intended job.

As an example, a device used as a data logger should only be updated with new versions of the data logger.

##### examples

- TTGO-T8-ESP32-Logger
- TTGO-T8-ESP32-Temp
- TTGO-T8-ESP32-Relay


### Debug

Messages depends of build level. If you pass -D CORE_DEBUG_LEVEL=3 to build flags, it enable the messages

### Sketch & other files

In this example a version 0.1.5  of firmware is currently in your ESP32 board, it would be updated when using the JSON example.

`firmwares.json` for this example:

```json
{
    "type": "m5stack_FOTA",
    "version": "0.1.6",
    "url": "http://10.130.0.141:8000/m5stack/firmware.img"
}
```

```cpp
#include <Arduino.h>
#include <esp32mOTA.h>
#include <WiFi.h>
#include "ota_rsa_pub_key.h"
namespace
{
    const char *ssid = "<your SSID name here>";
    const char *pass = "<your pass here>";

    const char *firmware_type = "m5stack_FOTA";
    const char *current_version = "0.1.6";
    const char *check_fw_URL = "http://10.130.0.141:8000/firmwares.json";
    String json_url(check_fw_URL);
}

esp32mOTA mOTA(firmware_type, current_version, rsa_pub_key, sizeof(rsa_pub_key));

void setup_wifi()
{
    delay(10);
    Serial.printf("Connecting to %s ", ssid);
    WiFi.begin(ssid, pass);
    while (WiFi.status() != WL_CONNECTED)
    {
        delay(500);
        Serial.print(".");
    }
    Serial.println("\nWF Connected!");
}

void setup()
{
    Serial.begin(115200);
    Serial.println(current_version);
    setup_wifi();

    json_url += "?id=";
    json_url += ESP.getEfuseMac();
}

void loop()
{
    bool updateNeeded = mOTA.execHTTPcheck(json_url);
    if (updateNeeded)
    {
        Serial.println("A newer firmware version was found --> update");
        mOTA.execOTA();
    }
    delay(2000);
}
```
### Verified images via signature

You can sign your firmware image with an RSA public/private key pair and have the ESP32 check if the signature is correct before
it switches over to the new image.
Provide your public key in a header file and place it at the same folder with main.cpp. 

`ota_rsa_pub_key.h` format example:

```cpp
static const unsigned char rsa_pub_key[] = R"~~~(-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA04D07cMpLUVQCLeNCUB0
IcKhKUG35JExPwqo58w/BviOueU6ibOROxf63kI+yljFg8B2aV1lB5Fi8WeftF6s
dex+Y4t5i/vBC2RlIcO9cNs1yxCVKkpTqMv4j2M9gdjyM5PAsk8VmIG/siPNiI56
MMO+1aSF6aQMaUW1kvIiMQM7d7NoqSuP+DHjYWCKrU2T3eMn/zxa9jIohyQcSfdV
uPJjZuvgmST7qHAk/7YR6lcrbB25+jqrRReloZFEvH0iSMHB+ruAihsVIrLNK6iE
kBF6UN5etYBez210Huouyneb2V7WzbLvBTf3E+fmTMyrZxPL4/DWfz0hhPkWmGpI
j1xLqknr6OTSEQ3f5YWU7byGEvs5fqaMokqR73gNjP5WzTBAFWaiH1PtaezasUtr
WZ7GegTepRvXta+A3XJVnwmhZbxB7uJsRkKxUQsqEMC+RDqH9RFalGZKaP2wrIce
TYTMhbKL6Gg/w7M514yqonIfoul2iKkN3wtlDxU7NL4bAbc6NRidgvOOLVKsNN2p
Oib3h1xgJfpW3y6kODCA71ZK47DkhS/eSR3vXGMJfx2uaas6lg5KiIo0KlHxzzMj
HqoLBoiNUfXqJ6kbAwo2o8/K/pQy06pjCCAKaozJPJ3jQl1Js22SsQKFo45UsQkD
RsvhLheT146a+Cba80NApvsCAwEAAQ==
-----END PUBLIC KEY-----
)~~~";
```

Create a key-pair to sign your firmware image:
```
openssl genrsa -aes256 -out priv_key.pem 4096
openssl rsa -in priv_key.pem -pubout > rsa_key.pub
```

Compile your code so you get your OTA update file (e.g. `firmware.bin`). Now it's time to create the signature:
```
# Create signature file
openssl dgst -sign priv_key.pem -keyform PEM -sha256 -out firmware.sign -binary firmware.bin

# throw it all in one file
cat firmware.sign firmware.bin > firmware.img
```

Upload `firmware.img` to your OTA server and point to it in your `firmware.json`

Last step, create an SPIFFS partition with your `rsa_key.pub` in it. The OTA update should not touch this partition during the update. You'll only need to distribute this partition once.

On the next update-check the ESP32 will download the `firmware.img` extract the first 512 bytes with the signature and check it together with the public key against the new image. If the signature check runs OK, it'll reset into the new firmware.

### Dependencies

- [semver.c by h2non](https://github.com/h2non/semver.c) for semantic versioning support. semver.c is licensed under [MIT](https://github.com/h2non/semver.c/blob/master/LICENSE).
- [ArduinoJson](https://github.com/bblanchon/ArduinoJson)

### Thanks to 
- The original of this library code was forked from [Chris Joyce's esp32FOTA](https://github.com/chrisjoyce911/esp32FOTA)


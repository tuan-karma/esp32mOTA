/*
This example demos the usage of `esp32mOTA` library - The minimalized for secure OTA firmware update for ESP32 chips.

Steps:
- Preparing your rsa key pair using openssl (see the README.md on the github for details.)
- Preparing a local or remote http server (local server using python in this example.)
- Write the code in the main.cpp file using esp32mOTA's APIs as in this file.
- Compose the firmwares.json file as seen in this folder.
- Compile the code on PIO --> copy the `<your_pio_project_dir>/.pio/build/<your_board_name>/firmware.bin` into a separate Directory. 
    It's recommended that you should place the firmware.bin file and rsa_key.pem files in the same directory for sigining convenience.
- Sign the firmware.bin (and concat the signature into) --> firmware.img. 
- Place `firmware.img` and `firmwares.json` into the above server's files directory.
- Run the http server, burn the initial code into your ESP32 board, and perform the OTA update test (with the increment of your firmware version).

*/

#include <Arduino.h>
#include <esp32mOTA.h>
#include <WiFi.h>
#include "ota_rsa_pub_key.h"
namespace
{
    const char *ssid = "xxx";
    const char *pass = "xxx";

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
/*
   esp32 firmware OTA
   Date: December 2018
   Author: Chris Joyce <https://github.com/chrisjoyce911/esp32FOTA/esp32FOTA>
   Purpose: Perform an OTA update from a bin located on a webserver (HTTP Only)

   Date: 2021-12-21
   Author: Moritz Meintker <https://thinksilicon.de>
   Remarks: Re-written/removed a bunch of functions around HTTPS. The library is
            now URL-agnostic. This means if you provide an https://-URL it will
            use the root_ca.pem (needs to be provided via LittleFS) to verify the
            server certificate and then download the ressource through an encrypted
            connection unless you set the allow_insecure_https option.
            Otherwise it will just use plain HTTP which will still offer to sign
            your firmware image.

    Date: 2022-08-24
    Author: Nguyen Anh Tuan <https://github.com/tuan-karma>
    Feature added: use the rsa_pub_key.h to embed the key into the fimrware. This feature helps:
    - Preventing someone with physical access to your esp32-board altering the rsa_pub_key in the SPI flash memory
    hence compromising the next firmware update.
    - Being able to update the rsa_key for the next version of your firmware conveniently.
*/

#include "esp32mOTA.h"
#include <Arduino.h>
#include <WiFi.h>
#include <HTTPClient.h>
#include <Update.h>
#include "ArduinoJson.h"

#include "mbedtls/pk.h"
#include "mbedtls/md.h"
#include "mbedtls/md_internal.h"
#include "esp_ota_ops.h"

#include <WiFiClientSecure.h>

esp32mOTA::~esp32mOTA()
{
    semver_free(&_firmwareVersion);
    semver_free(&_payloadVersion);
}

esp32mOTA::esp32mOTA(const char *firmwareType, const char* firmwareSemanticVersion, const unsigned char *public_key, size_t public_key_length)
    : _firmwareType(firmwareType), _public_key(public_key), _public_key_length(public_key_length)
{
    if (semver_parse(firmwareSemanticVersion, &_firmwareVersion))
    {
        log_e("Invalid semver string %s passed to constructor. Defaulting to 0", firmwareSemanticVersion);
        _firmwareVersion = semver_t{0};
    }

    char version_no[256] = {'\0'};
    semver_render(&_firmwareVersion, version_no);
    log_i("Current firmware version: %s", version_no);
}

// Check file signature
// https://techtutorialsx.com/2018/05/10/esp32-arduino-mbed-tls-using-the-sha-256-algorithm/
// https://github.com/ARMmbed/mbedtls/blob/development/programs/pkey/rsa_verify.c
bool esp32mOTA::validate_sig(const unsigned char *signature, const uint32_t firmware_size)
{
    int ret = 1;
    mbedtls_pk_context pk;
    mbedtls_md_context_t rsa;

    { // Check RSA public key:
        mbedtls_pk_init(&pk);
        if ((ret = mbedtls_pk_parse_public_key(&pk, _public_key, _public_key_length)) != 0)
        {
            log_e("Reading public key failed\n  ! mbedtls_pk_parse_public_key %d\n\n", ret);
            return false;
        }
    }

    if (!mbedtls_pk_can_do(&pk, MBEDTLS_PK_RSA))
    {
        log_e("Public key is not an rsa key -0x%x\n\n", -ret);
        return false;
    }

    const esp_partition_t *partition = esp_ota_get_next_update_partition(NULL);

    if (!partition)
    {
        log_e("Could not find update partition!");
        return false;
    }

    const mbedtls_md_info_t *mdinfo = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md_init(&rsa);
    mbedtls_md_setup(&rsa, mdinfo, 0);
    mbedtls_md_starts(&rsa);

    int bytestoread = SPI_FLASH_SEC_SIZE;
    int bytesread = 0;
    int size = firmware_size;

    uint8_t *_buffer = (uint8_t *)malloc(SPI_FLASH_SEC_SIZE);
    if (!_buffer)
    {
        log_e("malloc failed");
        return false;
    }
    // Serial.printf( "Reading partition (%i sectors, sec_size: %i)\r\n", size, bytestoread );
    while (bytestoread > 0)
    {
        // Serial.printf( "Left: %i (%i)               \r", size, bytestoread );

        if (ESP.partitionRead(partition, bytesread, (uint32_t *)_buffer, bytestoread))
        {
            // Debug output for the purpose of comparing with file
            /*for( int i = 0; i < bytestoread; i++ ) {
              if( ( i % 16 ) == 0 ) {
                Serial.printf( "\r\n0x%08x\t", i + bytesread );
              }
              Serial.printf( "%02x ", (uint8_t*)_buffer[i] );
            }*/

            mbedtls_md_update(&rsa, (uint8_t *)_buffer, bytestoread);

            bytesread = bytesread + bytestoread;
            size = size - bytestoread;

            if (size <= SPI_FLASH_SEC_SIZE)
            {
                bytestoread = size;
            }
        }
        else
        {
            log_e("partitionRead failed!");
            return false;
        }
    }
    free(_buffer);

    unsigned char *hash = (unsigned char *)malloc(mdinfo->size);
    mbedtls_md_finish(&rsa, hash);

    ret = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256,
                            hash, mdinfo->size,
                            (unsigned char *)signature, 512);

    free(hash);
    mbedtls_md_free(&rsa);
    mbedtls_pk_free(&pk);
    if (ret == 0)
    {
        return true;
    }
    // overwrite the frist few bytes so this partition won't boot!

    ESP.partitionEraseRange(partition, 0, ENCRYPTED_BLOCK_SIZE);

    return false;
}

// OTA Logic
void esp32mOTA::execOTA()
{
    int contentLength = 0;
    bool isValidContentType = false;

    HTTPClient http;
    WiFiClientSecure client;
    // http.setConnectTimeout( 1000 );
    http.setFollowRedirects(HTTPC_STRICT_FOLLOW_REDIRECTS);

    log_i("Connecting to: %s\r\n", _firmwareURL.c_str());
    if (_firmwareURL.indexOf("https") == 0)
    {
        // We're downloading from a secure URL, but we don't want to validate the root cert.
        client.setInsecure();
        http.begin(client, _firmwareURL);
    }
    else
    {
        http.begin(_firmwareURL);
    }

    const char *get_headers[] = {"Content-Length", "Content-type"};
    http.collectHeaders(get_headers, 2);

    int httpCode = http.GET();

    if (httpCode == HTTP_CODE_OK || httpCode == HTTP_CODE_MOVED_PERMANENTLY)
    {
        contentLength = http.header("Content-Length").toInt();
        String contentType = http.header("Content-type");
        if (contentType == "application/octet-stream")
        {
            isValidContentType = true;
        }
    }
    else
    {
        // Connect to webserver failed
        // May be try?
        // Probably a choppy network?
        log_i("Connection to %s failed. Please check your setup", _firmwareURL);
        // retry??
        // execOTA();
    }

    // Check what is the contentLength and if content type is `application/octet-stream`
    log_i("contentLength : %i, isValidContentType : %s", contentLength, isValidContentType ? "true" : "false");

    // check contentLength and content type
    if (contentLength && isValidContentType)
    {
        WiFiClient &client = http.getStream();

        if (_public_key)
        {
            // _public_key != nullptr --> need to check the signature
            // If firmware is signed, extract signature and decrease content-length by 512 bytes for signature
            contentLength = contentLength - 512;
        }
        // Check if there is enough to OTA Update
        bool canBegin = Update.begin(contentLength);

        // If yes, begin
        if (canBegin)
        {
            unsigned char signature[512];
            if (_public_key)
            {
                client.readBytes(signature, 512);
            }
            Serial.println("Begin OTA. This may take 2 - 5 mins to complete. Things might be quiet for a while.. Patience!");
            // No activity would appear on the Serial monitor
            // So be patient. This may take 2 - 5mins to complete
            size_t written = Update.writeStream(client);

            if (written == contentLength)
            {
                Serial.println("Written : " + String(written) + " successfully");
            }
            else
            {
                Serial.println("Written only : " + String(written) + "/" + String(contentLength) + ". Retry?");
                // retry??
                // execOTA();
            }

            if (Update.end())
            {
                if (_public_key)
                {
                    if (!validate_sig(signature, contentLength))
                    {

                        const esp_partition_t *partition = esp_ota_get_running_partition();
                        esp_ota_set_boot_partition(partition);

                        log_e("Signature check failed!");
                        http.end();
                        ESP.restart();
                        return;
                    }
                    else
                    {
                        log_i("Signature OK");
                    }
                }
                Serial.println("OTA done!");
                if (Update.isFinished())
                {
                    Serial.println("Update successfully completed. Rebooting.");
                    http.end();
                    ESP.restart();
                }
                else
                {
                    Serial.println("Update not finished? Something went wrong!");
                }
            }
            else
            {
                Serial.println("Error Occurred. Error #: " + String(Update.getError()));
            }
        }
        else
        {
            // not enough space to begin OTA
            // Understand the partitions and
            // space availability
            Serial.println("Not enough space to begin OTA");
            http.end();
        }
    }
    else
    {
        log_e("There was no content in the response");
        http.end();
    }
}

bool esp32mOTA::checkJSONManifest(JsonVariant JSONDocument)
{

    if (strcmp(JSONDocument["type"].as<const char *>(), _firmwareType) != 0)
    {
        log_i("Payload type in manifest %s doesn't match current firmware %s", JSONDocument["type"].as<const char *>(), _firmwareType);
        log_i("Doesn't match type: %s", _firmwareType);
        return false; // Move to the next entry in the manifest
    }
    log_i("Payload type in manifest %s matches current firmware %s", JSONDocument["type"].as<const char *>(), _firmwareType);

    semver_free(&_payloadVersion);
    if (JSONDocument["version"].is<uint16_t>())
    {
        log_i("JSON version: %d (int)", JSONDocument["version"].as<uint16_t>());
        _payloadVersion = semver_t{JSONDocument["version"].as<uint16_t>()};
    }
    else if (JSONDocument["version"].is<const char *>())
    {
        log_i("JSON version: %s (semver)", JSONDocument["version"].as<const char *>());
        if (semver_parse(JSONDocument["version"].as<const char *>(), &_payloadVersion))
        {
            log_e("Invalid semver string received in manifest. Defaulting to 0");
            _payloadVersion = semver_t{0};
        }
    }
    else
    {
        log_e("Invalid semver format received in manifest. Defaulting to 0");
        _payloadVersion = semver_t{0};
    }

    char version_no[256] = {'\0'};
    semver_render(&_payloadVersion, version_no);
    log_i("Payload firmware version: %s", version_no);

    if (JSONDocument["url"].is<String>())
    {
        // We were provided a complete URL in the JSON manifest - use it
        _firmwareURL = JSONDocument["url"].as<String>();
        if (JSONDocument["host"].is<String>()) // If the manifest provides both, warn the user
            log_w("Manifest provides both url and host - Using URL");
    }
    else if (JSONDocument["host"].is<String>() && JSONDocument["port"].is<uint16_t>() && JSONDocument["bin"].is<String>())
    {
        // We were provided host/port/bin format - Build the URL
        if (JSONDocument["port"].as<uint16_t>() == 443 || JSONDocument["port"].as<uint16_t>() == 4433)
            _firmwareURL = "https://";
        else
            _firmwareURL = "http://";

        _firmwareURL += JSONDocument["host"].as<String>() + ":" + String(JSONDocument["port"].as<uint16_t>()) + JSONDocument["bin"].as<String>();
    }
    else
    {
        // JSON was malformed - no firmware target was provided
        log_e("JSON manifest was missing both 'url' and 'host'/'port'/'bin' keys");
        return false;
    }

    if (semver_compare(_payloadVersion, _firmwareVersion) == 1)
    {
        _firmwareURL += "?id=";
        _firmwareURL += ESP.getEfuseMac();
        return true;
    }
    return false;
}

bool esp32mOTA::execHTTPcheck(const String& json_url)
{
    log_i("Getting HTTP: %s", json_url.c_str());
    log_i("------");
    if ((WiFi.status() != WL_CONNECTED))
    { // Check the current connection status
        log_w("WiFi not connected - skipping HTTP check");
        return false; // WiFi not connected
    }

    HTTPClient http;
    WiFiClientSecure client;
    http.setFollowRedirects(HTTPC_STRICT_FOLLOW_REDIRECTS);

    // if (checkURL.substring(0, 5) == "https")
    if (json_url.indexOf("https") == 0)
    {
        // We're downloading from a secure port, but we don't want to validate the root cert.
        client.setInsecure();
        http.begin(client, json_url);
    }
    else
    {
        http.begin(json_url); // Specify the URL
    }
    int httpCode = http.GET(); // Make the request

    if (httpCode == HTTP_CODE_OK || httpCode == HTTP_CODE_MOVED_PERMANENTLY)
    { // Check is a file was returned

        String payload = http.getString();

        int str_len = payload.length() + 1;
        char JSONMessage[str_len];
        payload.toCharArray(JSONMessage, str_len);

        DynamicJsonDocument JSONResult(2048);
        DeserializationError err = deserializeJson(JSONResult, JSONMessage);

        http.end(); // We're done with HTTP - free the resources

        if (err)
        { // Check for errors in parsing
            log_e("Parsing failed");
            return false;
        }

        if (JSONResult.is<JsonArray>())
        {
            // We already received an array of multiple firmware types
            JsonArray arr = JSONResult.as<JsonArray>();
            for (JsonVariant JSONDocument : arr)
            {
                if (checkJSONManifest(JSONDocument))
                {
                    return true;
                }
            }
        }
        else if (JSONResult.is<JsonObject>())
        {
            if (checkJSONManifest(JSONResult.as<JsonVariant>()))
                return true;
        }

        return false; // We didn't get a hit against the above, return false
    }
    else
    {
        log_e("Error on HTTP request");
        http.end();
        return false;
    }
}

/**
 * This function return the new version of new firmware
 */
int esp32mOTA::getPayloadVersion()
{
    log_w("int esp32mOTA::getPayloadVersion() only returns the major version from semantic version strings. Use void esp32mOTA::getPayloadVersion(char * version_string) instead!");
    return _payloadVersion.major;
}

void esp32mOTA::getPayloadVersion(char *version_string)
{
    semver_render(&_payloadVersion, version_string);
}

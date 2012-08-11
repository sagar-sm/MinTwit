/*
 * Copyright 2012 Sagar Mohite

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

 */

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net.Http;
using Windows.Storage;
using Windows.Storage.Streams;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using System.Security;


namespace Mintwit
{
    class OAuthControls
    {
        public async static Task<OAuthToken> GetRequestTokenAsync(string ConsumerKey, string ConsumerSecret)
        {
            SortedDictionary<string, string> sd = new SortedDictionary<string, string>();
            string oauth_nonce = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(DateTime.Now.Ticks.ToString()));
            string utc_time = Globalv.unix_timestamp().ToString();
            sd.Add("oauth_version", "1.0");
            sd.Add("oauth_callback", "oob");
            sd.Add("oauth_consumer_key", ConsumerKey);
            sd.Add("oauth_nonce", oauth_nonce);
            sd.Add("oauth_signature_method", "HMAC-SHA1");
            sd.Add("oauth_timestamp", utc_time);

            string baseString = String.Empty;
            baseString += "POST" + "&";
            baseString += Uri.EscapeDataString(
                "https://api.twitter.com/oauth/request_token")
                + "&";

            foreach (KeyValuePair<string, string> entry in sd)
            {
                baseString += Uri.EscapeDataString(entry.Key +
                    "=" + entry.Value + "&");
            }

            baseString =
                baseString.Substring(0, baseString.Length - 3);

            string consumerSecret = ConsumerSecret;


            string signingKey = Uri.EscapeDataString(consumerSecret) + "&";

            // Create a MacAlgorithmProvider object for the specified algorithm.
            MacAlgorithmProvider objMacProv = MacAlgorithmProvider.OpenAlgorithm("HMAC_SHA1");

            // Demonstrate how to retrieve the name of the algorithm used.
            String strNameUsed = objMacProv.AlgorithmName;

            // Create a buffer that contains the the message to be signed.
            BinaryStringEncoding encoding = BinaryStringEncoding.Utf8;
            IBuffer buffMsg = CryptographicBuffer.ConvertStringToBinary(baseString, encoding);

            // Create a key to be signed with the message.
            IBuffer keyMaterial = CryptographicBuffer.ConvertStringToBinary(signingKey, BinaryStringEncoding.Utf8);
            CryptographicKey hmacKey = objMacProv.CreateKey(keyMaterial);

            // Sign the key and message together.
            IBuffer buffHMAC = CryptographicEngine.Sign(hmacKey, buffMsg);

            // Verify that the HMAC length is correct for the selected algorithm
            if (buffHMAC.Length != objMacProv.MacLength)
            {
                throw new Exception("Error computing digest");
            }

            string signatureString = CryptographicBuffer.EncodeToBase64String(buffHMAC);

            //prepare for sending
            HttpClient cli = new HttpClient();
            cli.DefaultRequestHeaders.ExpectContinue = false;
            cli.DefaultRequestHeaders.ConnectionClose = true;

            //auth headers
            string authorizationHeaderParams = String.Empty;
            //authorizationHeaderParams += "OAuth ";
            authorizationHeaderParams += "oauth_nonce=" + "\"" + Uri.EscapeDataString(oauth_nonce) + "\",";
            authorizationHeaderParams += "oauth_callback=" + "\"" + Uri.EscapeDataString("oob") + "\",";
            authorizationHeaderParams += "oauth_signature_method=" + "\"" + Uri.EscapeDataString("HMAC-SHA1") + "\",";
            authorizationHeaderParams += "oauth_timestamp=" + "\"" + Uri.EscapeDataString(utc_time) + "\",";
            authorizationHeaderParams += "oauth_consumer_key=" + "\"" + Uri.EscapeDataString(ConsumerKey) + "\",";
            authorizationHeaderParams += "oauth_signature=" + "\"" + Uri.EscapeDataString(signatureString) + "\",";
            authorizationHeaderParams += "oauth_version=" + "\"" + Uri.EscapeDataString("1.0") + "\"";
            cli.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("OAuth", authorizationHeaderParams);



            var MuTweetResponse = await cli.PostAsync(new Uri(@"https://api.twitter.com/oauth/request_token", UriKind.Absolute), null);
            string resp = await MuTweetResponse.Content.ReadAsStringAsync();

            string[] resp_split = resp.Split('&');
            string requesttoken = resp_split[0].Substring(12);
            string requesttokensecret = resp_split[1].Substring(19);

            OAuthToken ret = new OAuthToken();
            ret.Token = requesttoken;
            ret.TokenSecret = requesttokensecret;

            return ret;
        }

        public async static Task<OAuthToken> ExchangeRequestWithAccessTokenAsync(string ConsumerKey, string ConsumerSecret, OAuthToken RequestToken, string pin)
        {
            SortedDictionary<string, string> sd = new SortedDictionary<string, string>();
            string oauth_nonce = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(DateTime.Now.Ticks.ToString()));
            string utc_time = Globalv.unix_timestamp().ToString();
            sd.Add("oauth_version", "1.0");
            sd.Add("oauth_callback", "oob");
            sd.Add("oauth_consumer_key", ConsumerKey);
            sd.Add("oauth_nonce", oauth_nonce);
            sd.Add("oauth_signature_method", "HMAC-SHA1");
            sd.Add("oauth_timestamp", utc_time);
            sd.Add("oauth_token", RequestToken.Token);
            sd.Add("oauth_verifier", pin);

            string baseString = String.Empty;
            baseString += "POST" + "&";
            baseString += Uri.EscapeDataString(
                "https://api.twitter.com/oauth/access_token")
                + "&";

            foreach (KeyValuePair<string, string> entry in sd)
            {
                baseString += Uri.EscapeDataString(entry.Key +
                    "=" + entry.Value + "&");
            }

            baseString =
                baseString.Substring(0, baseString.Length - 3);

            string consumerSecret = ConsumerSecret;
            string oauth_token_secret = RequestToken.TokenSecret;

            string signingKey = Uri.EscapeDataString(consumerSecret) + "&" + Uri.EscapeDataString(oauth_token_secret);

            // Create a MacAlgorithmProvider object for the specified algorithm.
            MacAlgorithmProvider objMacProv = MacAlgorithmProvider.OpenAlgorithm("HMAC_SHA1");

            // Demonstrate how to retrieve the name of the algorithm used.
            String strNameUsed = objMacProv.AlgorithmName;

            // Create a buffer that contains the the message to be signed.
            BinaryStringEncoding encoding = BinaryStringEncoding.Utf8;
            IBuffer buffMsg = CryptographicBuffer.ConvertStringToBinary(baseString, encoding);

            // Create a key to be signed with the message.
            IBuffer keyMaterial = CryptographicBuffer.ConvertStringToBinary(signingKey, BinaryStringEncoding.Utf8);
            CryptographicKey hmacKey = objMacProv.CreateKey(keyMaterial);

            // Sign the key and message together.
            IBuffer buffHMAC = CryptographicEngine.Sign(hmacKey, buffMsg);

            // Verify that the HMAC length is correct for the selected algorithm
            if (buffHMAC.Length != objMacProv.MacLength)
            {
                throw new Exception("Error computing digest");
            }

            string signatureString = CryptographicBuffer.EncodeToBase64String(buffHMAC);

            //prepare for sending
            HttpClient cli = new HttpClient();
            cli.DefaultRequestHeaders.ExpectContinue = false;
            cli.DefaultRequestHeaders.ConnectionClose = true;

            //auth headers
            string authorizationHeaderParams = String.Empty;
            //authorizationHeaderParams += "OAuth ";
            authorizationHeaderParams += "oauth_nonce=" + "\"" + Uri.EscapeDataString(oauth_nonce) + "\",";
            authorizationHeaderParams += "oauth_callback=" + "\"" + Uri.EscapeDataString("oob") + "\",";
            authorizationHeaderParams += "oauth_signature_method=" + "\"" + Uri.EscapeDataString("HMAC-SHA1") + "\",";
            authorizationHeaderParams += "oauth_timestamp=" + "\"" + Uri.EscapeDataString(utc_time) + "\",";
            authorizationHeaderParams += "oauth_consumer_key=" + "\"" + Uri.EscapeDataString(ConsumerKey) + "\",";
            authorizationHeaderParams += "oauth_token=" + "\"" + Uri.EscapeDataString(RequestToken.Token) + "\",";
            authorizationHeaderParams += "oauth_signature=" + "\"" + Uri.EscapeDataString(signatureString) + "\",";
            authorizationHeaderParams += "oauth_verifier=" + "\"" + pin + "\",";
            authorizationHeaderParams += "oauth_version=" + "\"" + Uri.EscapeDataString("1.0") + "\"";
            cli.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("OAuth", authorizationHeaderParams);

            var MuTweetResponse = await cli.PostAsync(new Uri(@"https://api.twitter.com/oauth/access_token", UriKind.Absolute), null);
            string resp = await MuTweetResponse.Content.ReadAsStringAsync();

            string[] resp_split = resp.Split('&');
            string requesttoken = resp_split[0].Substring(12);
            string requesttokensecret = resp_split[1].Substring(19);

            OAuthToken ret = new OAuthToken();
            ret.Token = requesttoken;
            ret.TokenSecret = requesttokensecret;

            return ret;
        }

        public async static Task<Uri> GetAuthURLAsync(OAuthToken TwitterRequestToken)
        {
            string auth_url = @"https://api.twitter.com/oauth/authenticate?oauth_token=" + TwitterRequestToken.Token;
            Uri auth = new Uri(auth_url);
            return auth;
        }

    }
}

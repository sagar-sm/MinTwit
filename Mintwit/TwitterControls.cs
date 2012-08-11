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
    class TwitterControls
    {
        public async static Task<string> PostStatusAsync(string status, OAuthToken TwitterAccessToken, string ConsumerKey, string ConsumerSecret)
        {
            SortedDictionary<string, string> sd = new SortedDictionary<string, string>();
            string oauth_nonce = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(DateTime.Now.Ticks.ToString()));
            string utc_time = Globalv.unix_timestamp().ToString();
            sd.Add("status", Uri.EscapeDataString(status));
            sd.Add("include_entities", "true");
            sd.Add("oauth_version", "1.0");
            sd.Add("oauth_consumer_key", ConsumerKey);
            sd.Add("oauth_nonce", oauth_nonce);
            sd.Add("oauth_signature_method", "HMAC-SHA1");
            sd.Add("oauth_timestamp", utc_time);
            sd.Add("oauth_token", TwitterAccessToken.Token);

            string baseString = String.Empty;
            baseString += "POST" + "&";
            baseString += Uri.EscapeDataString(
                "http://api.twitter.com/1/statuses/update.json")
                + "&";

            foreach (KeyValuePair<string, string> entry in sd)
            {
                baseString += Uri.EscapeDataString(entry.Key +
                    "=" + entry.Value + "&");
            }

            baseString =
                baseString.Substring(0, baseString.Length - 3);

            //shh... secrets here!
            string consumerSecret = ConsumerSecret;

            string oauth_token_secret = TwitterAccessToken.TokenSecret;

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
            authorizationHeaderParams += "oauth_signature_method=" + "\"" + Uri.EscapeDataString("HMAC-SHA1") + "\",";
            authorizationHeaderParams += "oauth_timestamp=" + "\"" + Uri.EscapeDataString(utc_time) + "\",";
            authorizationHeaderParams += "oauth_consumer_key=" + "\"" + Uri.EscapeDataString(ConsumerKey) + "\",";
            authorizationHeaderParams += "oauth_token=" + "\"" + Uri.EscapeDataString(TwitterAccessToken.Token) + "\",";
            authorizationHeaderParams += "oauth_signature=" + "\"" + Uri.EscapeDataString(signatureString) + "\",";
            authorizationHeaderParams += "oauth_version=" + "\"" + Uri.EscapeDataString("1.0") + "\"";
            cli.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("OAuth", authorizationHeaderParams);

            string postBody = "status=" + Uri.EscapeDataString(status) + "&include_entities=true";
            HttpContent tweet = new StringContent(postBody);
            tweet.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/x-www-form-urlencoded");

            var MuTweetResponse = await cli.PostAsync(new Uri(@"http://api.twitter.com/1/statuses/update.json", UriKind.Absolute), tweet);
            return await MuTweetResponse.Content.ReadAsStringAsync();
        }

        public async static Task<string> GetUserTimelineAsync(string userid, OAuthToken TwitterAccessToken, string ConsumerKey, string ConsumerSecret)
        {
            SortedDictionary<string, string> sd = new SortedDictionary<string, string>();
            string oauth_nonce = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(DateTime.Now.Ticks.ToString()));
            string utc_time = Globalv.unix_timestamp().ToString();
            sd.Add("include_rts", "true");
            sd.Add("include_entities", "true");
            sd.Add("user_id", userid);
            sd.Add("count", "20");
            sd.Add("oauth_version", "1.0");
            sd.Add("oauth_consumer_key", ConsumerKey);
            sd.Add("oauth_nonce", oauth_nonce);
            sd.Add("oauth_signature_method", "HMAC-SHA1");
            sd.Add("oauth_timestamp", utc_time);
            sd.Add("oauth_token", TwitterAccessToken.Token);

            string baseString = String.Empty;
            baseString += "GET" + "&";
            baseString += Uri.EscapeDataString(
                "https://api.twitter.com/1/statuses/user_timeline.json?")
                + "&";

            foreach (KeyValuePair<string, string> entry in sd)
            {
                baseString += Uri.EscapeDataString(entry.Key +
                    "=" + entry.Value + "&");
            }

            baseString =
                baseString.Substring(0, baseString.Length - 3);

            //shh... secrets here!
            string consumerSecret = ConsumerSecret;

            string oauth_token_secret = TwitterAccessToken.TokenSecret;

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
            authorizationHeaderParams += "oauth_signature_method=" + "\"" + Uri.EscapeDataString("HMAC-SHA1") + "\",";
            authorizationHeaderParams += "oauth_timestamp=" + "\"" + Uri.EscapeDataString(utc_time) + "\",";
            authorizationHeaderParams += "oauth_consumer_key=" + "\"" + Uri.EscapeDataString(ConsumerKey) + "\",";
            authorizationHeaderParams += "oauth_token=" + "\"" + Uri.EscapeDataString(TwitterAccessToken.Token) + "\",";
            authorizationHeaderParams += "oauth_signature=" + "\"" + Uri.EscapeDataString(signatureString) + "\",";
            authorizationHeaderParams += "oauth_version=" + "\"" + Uri.EscapeDataString("1.0") + "\"";
            cli.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("OAuth", authorizationHeaderParams);

            var resp = await cli.GetAsync(new Uri(@"https://api.twitter.com/1/statuses/user_timeline.json?include_entities=true&include_rts=true&user_id=" + userid + "&count=20", UriKind.Absolute));
            return await resp.Content.ReadAsStringAsync();
        }

        public async static Task<string> SearchTweetsAsync(string SearchQuery)
        {
            HttpClient cli = new HttpClient();
            string get_latest_tweets = @"http://search.twitter.com/search.json?q=" + Uri.EscapeDataString(SearchQuery) + @"&rpp=20&include_entities=true&lang=en&result_type=mixed";
            HttpResponseMessage get_tweets = await cli.GetAsync(get_latest_tweets);
            return await get_tweets.Content.ReadAsStringAsync();

        }


    }
}

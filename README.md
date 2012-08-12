MinTwit
==========

*MinTwit* is a Twitter library for WinRT based apps(Metro style) for Windows 8, written in C#.
The current version provides -    
*   OAuth Authentication.   
*   Update Status aka tweet.   
*   Get User Timeline.   
*   Search for hashtags/terms etc.    
    
**NOTE 1:** For information about creating a desktop application for Twitter, visit the [Twitter Developers Site](http://dev.twitter.com/)    
**NOTE 2:** The Async functions return an awaitable Task`<T>` value. For more info read [Diving deep with WinRT and await](http://blogs.msdn.com/b/windowsappdev/archive/2012/04/24/diving-deep-with-winrt-and-await.aspx)
    
0. Prerequisites
------------------
1. In VS, Add a reference to the file MinTwit.dll
2. Import the namespace "MinTwit" in your project. 

    using MinTwit;
3. [Create an application](https://dev.twitter.com/apps/new) for Twitter and use "oob" as the callback url.
4. The ConsumerKey and ConsumerSecret that you'll get shall be used later.

1. Authentication
---------------------
MinTwit uses 3 step PIN based [OAuth](http://oauth.net) to provide authorized access to Twitter's API. The process is fairly simple - 

    //1. Send out a request for getting an OAuth RequestToken -     
    //Provide your ConsumerKey
	    OAuthToken RequestToken = new OAuthToken();
	    RequestToken = await OAuthControls.GetRequestTokenAsync(string ConsumerKey, string ConsumerSecret);		
    //2. Get the authorization URL from the RequestToken as follows -   
        Uri auth_uri = await OAuthControls.GetAuthURLAsync(OAuthToken TwitterRequestToken);
    
	//3. Navigate to the auth_uri via a Launcher   
        var success = await Windows.System.Launcher.LaunchUriAsync(auth_uri);
	    if(success)
	    {
	    	//code to provide the user a way to input the PIN code shown on the browser
	    }
    
	//4. Exchange the RequestToken with an AccessToken    
	   	OAuthToken AccessToken = await OAuthControls.ExchangeRequestWithAccessTokenAsync(string ConsumerKey, string ConsumerSecret, OAuthToken RequestToken, string pin);

2. Post Status Updates
------------------------
        string response = await Twitter.Post_status(TweetBox.Text);
Updating status provides a response message on success as given [here](https://dev.twitter.com/docs/api/1/post/statuses/update). You can use the [JSON.NET](http://james.newtonking.com/projects/json-net.aspx) library by James Newton-King for parsing JSON.

3. Get User Timeline
----------------------
        string response = await TwitterControls.GetUserTimelineAsync(string userid, OAuthToken TwitterAccessToken, string ConsumerKey, string ConsumerSecret);
See [response format](https://dev.twitter.com/docs/api/1/get/statuses/user_timeline)

4. Search
----------
        string response = await TwitterControls.SearchTweetsAsync(string SearchQuery);
See [response format](https://dev.twitter.com/docs/api/1/get/search)

###Release Notes:
**Author:** [Sagar Mohite](http://seaflection.com)   
**Release Date:** 12 August 2012   
MinTwit Version 1.0.0   
License: [Apache License, Version 2.0](http://opensource.org/licenses/Apache-2.0)
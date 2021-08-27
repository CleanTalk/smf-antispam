# SMF Antispam mod
================

[![Build Status](https://travis-ci.org/CleanTalk/smf-antispam.svg)](https://travis-ci.org/CleanTalk/smf-antispam)

* **Version:** 2.35
* **License:** GNU General Public License  
* **Compatible with:** SMF 2.0 and up  
* **Languages:** English, Russian  
* **Mod page:** http://custom.simplemachines.org/mods/index.php?mod=3851
* **Github repository:** https://github.com/CleanTalk/smf-antispam  
* **Changelog:** https://github.com/CleanTalk/smf-antispam/blob/master/CHANGELOG  

### Description
Anti-Spam by CleanTalk mod with protection against spam bots and manual spam.
No Captcha, no questions, no counting animals, no puzzles, no math.

**Extension info**  
We have developed an anti-spam extension for SMF that would provide maximum protection from spam. You can provide for your visitors a simple and convenient form of posts/registrations without annoying CAPTCHAs and puzzles. Our invisible protection blocks up to 100% of spam bots.

**Features**  
* Deny signups of spam bots
* If necessary require administrator approval for new members
* Antispam test for the first post on board for Newly registered members


**Low false/positive rate**  
This MOD uses multiple anti-spam tests to filter spam bots with lower false/positive rate as possible. Multiple anti-spam tests avoid false/positive blocks for real website visitors even if one of the tests failed.

**Spam attacks log**  
Service CleanTalk (this plugin is a client application for CleanTalk anti-spam service) records all filtered comments, registration and other spam attacks in the "Log of spam attacks" and stores the data in the log up to 45 days. Using the log, you can ensure reliable protection of your website from spam and no false/positive filtering.

**Private blacklists**  
Automatically block comments and registrations from your private black IP/email address list. This option helps to strengthen the protection from a manual spam or block unwanted comments from users. You can add not only the certain IP addresses but also a separate subnet to your personal blacklist.

**Blocking users by country**  
Automatically block comments and registrations from the countries you have set a ban for. This option is useful in cases of manual spam protection and for protection enhancement. If your site is not intended for an international audience and you do not expect comments/users from other countries.

**Blocking comments by "stop words"**  
You can block comments which contain "stop words" to enhance spam filtering and messages with obscene words blocking. You can add particular words or phrases.

**Check existing users for spam**  
With the help of anti-spam by CleanTalk you can inspect through existing accounts to find and quickly delete spam users at once.

**SpamFireWall**  
CleanTalk has an advanced option "SpamFireWall". This option allows blocking the most active spam bots before they get access to your website. It prevents spam bots from loading website pages so your web server doesn't have to perform all scripts on these pages. Also, it prevents scanning of pages of the website by spam bots. Therefore SpamFireWall significantly reduces the load on your web server. SpamFireWall also makes CleanTalk the two-step protection from spam bots. SpamFireWall is the first step and it blocks the most active spam bots. CleanTalk Anti-Spam is the second step and checks all other requests on the website in the moment of submitting comments/registers etc.

**How SpamFireWall works?**  
* The visitor enters to your website.
* HTTP request data are being checked in the nearly 5.8 million of the identified spambot IPs.
* If it is an active spambot, the bot gets a blank page, if it is a visitor then he receives a normal page. This process is completely transparent for the visitors.


All the CleanTalk SpamFireWall activity is being logged in the process of filtering.

**Private blacklist for SpamFireWall**  
It allows you to add individual IP addresses and subnets to SpamFireWall. It blocks the attacks from IP addresses which are not included in the SFW base yet. This option can help to block HTTP/HTTPS DDoS, SQL, brute force attacks and any others that made it through the HTTP/HTTPS. You can add not only the certain IP addresses but also a separate subnet to your personal blacklist.

The CleanTalk is premium anti-spam for SMF, please look at the  pricing. We try to provide the service at the highest level and we can not afford to offer a free version of our service, as this will immediately affect the quality of providing anti-spam protection. Paying for a year of service, you save a lot more and get:

* 100% protection against spambots
* Time and resources saving
* More registrations/comments/visitors
* Protect several websites at once at different CMS
* Easy to install and use
* Traffic acquisition and user loyalty
* 24/7 technical support
* Clear statistics
* No captcha, puzzles, etc.
* Free mobile app

Also, you can use CleanTalk app for iPhone/iPad to control anti-spam service on web-site or control comments, signups, contacts, and orders.

**How to install the CleanTalk anti-spam MOD**

1. Go to Admin —> Package Manager.
2. Click the button Download Packages.
3. In the "Package servers" section press the string [ Browse ].
4. Find "Security and Moderation" section in the end of the list.
5. Press the string [ Download ] near the module's name "Anti-spam by CleanTalk".
6. Press the string [ Install Mod ].
7. Press the button "Install Now" at the bottom of the page.
8. You will be redirected to the module's settings after you install it (or you can go to the settings page manually: Admin —> Package Manager, Configuration —> Modification Settings —> Antispam by CleanTalk). Copy your access key from your CleanTalk Control Panel, setup the module and press the button "Save".
Go to Dashboard to see the anti-spam status, add new websites or manage existing ones! Please check your email to get account password.

**Admin Settings**  
Mod has admin settings on page Admin - Features and options - Configuration - Modification settings - Antispam by CleanTalk

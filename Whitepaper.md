# White Paper: Killing messenger phishing, with passkeys, blackjack, and hybrid

**Version 0.1 December 17th 2024**

## TL;DR:

Messaging apps are increasingly vulnerable to phishing attacks, particularly through QR-based cross-device session sharing, which has become a target for sophisticated phishing techniques. In this whitepaper, we provide detailed diagrams and code samples to demonstrate how passkeys can effectively prevent these attacks.

[https://github.com/DaryaScam](https://github.com/DaryaScam)

## About the author:

Yuriy Ackermann is a seasoned security and authentication specialist with extensive expertise in standards architecture, penetration testing, and large-scale project management. As a former Technical Manager at the FIDO Alliance, Yuriy contributed significantly to the development of FIDO2, WebAuthn, and other industry-leading authentication standards. He has been instrumental in creating certification programs, conducting workshops worldwide, [and shaping the global adoption of secure authentication technologies.](https://github.com/yackermann/awesome-webauthn) [An accomplished writer and speaker, Yuriy is the creator of a popular FIDO/passkeys blog](https://medium.com/@yackermann). His passion for pushing the boundaries of technology is matched by his dedication to user-centric design and practical implementations in cybersecurity.

## Abstract

Modern messaging apps offer users multiple ways to access their services. While mobile apps remain the primary platform for most users, many seek more versatile options, such as tablet apps on Android or iPadOS. Others prefer the convenience of desktop apps on Windows, macOS, or Linux, or may simply want to open a quick session in their web browser.

However, the current methods for cross-device session sharing are inherently insecure and vulnerable to phishing attacks.

The past two years have seen a sharp rise in attacks targeting cross-device session sharing, driven by the increasing user shift to siloed hybrid social platforms like `Telegram`, `WhatsApp`, `WeChat`, and `Discord`. Messaging apps are no longer used solely for P2P communication; they now function as social media hubs. Telegram, in particular, stands out for hosting a wide array of independent news channels, bloggers, and social service accounts, especially in regions like Ukraine and Russia.

This evolving usage, coupled with the harsh realities of the war in Ukraine and the prevalence of disinformation campaigns, has significantly increased the value of chat user accounts. People use these platforms daily to connect with friends, access news, participate in discussions, and engage with social services. This makes messaging apps prime targets for a wide spectrum of attackers—from cybercriminals focused on identity theft to state-sponsored hacker groups conducting espionage. As a result, the threat landscape for messaging apps is more dangerous than ever before.

An attacker’s potential gains extend far beyond sending messages on your behalf. They can often access your entire message history, extract sensitive documents such as passports or IDs (a common global practice), and send messages without your knowledge. Additionally, attackers can manipulate communications by deleting sent messages to cover their tracks, making the breach even more insidious.

These attacks are well known, and is being abused for the last decade, as described in [2018 paper by Ryan Heartfield and George Loukas from Cambridge University.](https://www.researchgate.net/publication/322476901_Protection_Against_Semantic_Social_Engineering_Attacks) These attacks have been raising in volume across the globe in the last 24 months, with evidence of them in Russia, Ukraine, [Singapore](https://stomp.straitstimes.com/singapore-seen/now-even-scanning-qr-code-to-use-desktop-version-of-whatsapp-may-not-be-safe-thanks), Iran, [China](https://www.fortinet.com/blog/threat-research/qr-code-phishing-attempts-to-steal-credentials-from-chinese-language-users), [US](https://nz.norton.com/blog/online-scams/whatsapp-scams), etc. 

[Kuba Gretzky had written a great article on how these attacks work, and even added it to the latest version of Evilginx phishing frameworks.](https://breakdev.org/evilqr-phishing/) 

However nothing is lost, and recent development in passkey ecosystem means that we are ready to fight back, and kill messenger phishing, once and for all, hence this paper existing in the first place.

## How modern messengers work?

A typical messenger employs a straightforward approach using QR codes for challenge and WebSocket connections for response. Here's how it typically works:

1. **Session Registration:** A new session is initiated with the WebSocket server.
2. **QR Code Presentation:** The server generates a QR code containing the session ID and other relevant information. The user scans this code with the mobile app.
3. **User Consent (Optional):** Depending on the app, the user may need to explicitly approve the new session on their primary device.
4. **Session Communication:** Once approved, the app subscribes to the shared session ID and begins communicating with the web session.

![Diagram 1, Standard session sharing flow for messaging apps.](White%20Paper%20Killing%20messenger%20phishing,%20with%20passk%20141cf1aba98e80ea9bcfee7353a22623/StandardMessagerSession.drawio.png)

Diagram 1, Standard session sharing flow for messaging apps.

Since there is no explicit proximity check or phishing protection, an attacker can simply forward their challenge QR code to the victim. The victim, unknowingly, authenticates the attacker's session, granting the attacker access to all of the user's private information.

This puts the victim at risk of the following consequences:

- **Spam and Fraud:** The attacker can send fake messages from the victim’s account to their contacts, requesting money or distributing malware. They can also delete these messages, leaving the victim unaware of the activity.
- **Surveillance:** The victim’s private chats, subscribed channels, and likes or reactions can be accessed by the attacker, creating severe risks for those in politically sensitive situations, such as activists in oppressive regimes like Russia or Belarus.
- **Identity Theft:** If the victim has shared sensitive documents like passports or driver’s licenses, the attacker can exploit them for fraudulent purposes.
- **Account Resale:** The victim’s account can be sold to other criminals or even governments, further exposing their personal information.

Some messaging apps demonstrate better security practices than others. For instance, Signal restricts the sharing of past messages with its desktop app, limiting the impact of an attack to new messages. However, this still leaves future communications exposed.

Apps like `Discord` and `Viber` allow users to log in using a username and password, which poses risks, while `Telegram`, `WhatsApp`, and `Signal` mandate explicit authentication via their mobile apps, providing an additional layer of protection.

Many messaging platforms also offer desktop apps that share similar security vulnerabilities with web session QR code-based flows, making them potential targets for exploitation.

This white paper addresses these challenges by proposing three comprehensive approaches to enhance the security of web sessions, desktop apps, and traditional authentication methods. These solutions are built around the adoption of phishing-resistant passkeys and the underlying technologies that make them feasible, providing a robust framework for secure communication in modern messaging applications.

In summary, this paper provides guidelines, and code samples for three specific scenarios:

1. **Phishing-Resistant Authorisation for Mobile-to-Web Sessions**:
    
    How can we securely authorise a web app session using the mobile app as the root of trust? This is relevant for platforms like `WhatsApp`, `Telegram`, and `Discord`.
    
2. **Phishing-Resistant Authorisation for Mobile-to-Desktop Sessions**:
    
    How can we securely authorise a desktop app session using the mobile app as the root of trust? This applies to all messaging platforms.
    
3. **Phishing-Resistant Authentication for Centralised Messaging Apps**:
    
    How can we enable secure, phishing-resistant authentication for centralised messaging platforms like `Viber` and `Discord`?
    

## Quick introduction to FIDO, passkeys, and hybrid transport.

Passkeys, also known as FIDO credentials or WebAuthn credentials, are a phishing-resistant authentication protocol based on the CTAP2 and WebAuthn standards.

The protocol’s core concept is straightforward:

- Generate a unique key pair for each key enrolment (registration).
- Use a signature-based challenge-response scheme.
- Ensure every transaction includes a browser-verified origin.

![Diagram 2, Passkeys authentication](White%20Paper%20Killing%20messenger%20phishing,%20with%20passk%20141cf1aba98e80ea9bcfee7353a22623/webauthn-03-ReplayAttack-svg-1497775794708.png)

Diagram 2, Passkeys authentication

This gives websites explicit trust in authentication security and makes phishing attacks impossible. There’s no need to store sensitive static secrets like passwords, and every authentication provides signed, verified session details. Attackers can’t phish the user because the browser enforces the origin, and TLS.

The communication between a thing that generates signatures, aka authenticator, and a client, aka browser, is done using CTAP protocol.

![Diagram 3, Passkeys ecosystem overview, discussing CTAP, WebAuthn and transports.](White%20Paper%20Killing%20messenger%20phishing,%20with%20passk%20141cf1aba98e80ea9bcfee7353a22623/Passkey_architecture.drawio.png)

Diagram 3, Passkeys ecosystem overview, discussing CTAP, WebAuthn and transports.

Passkeys are now widely available through platform providers, offering built-in passkey and password management solutions. Examples include Google Password Manager, Apple’s iCloud Passwords, and Microsoft Authenticator (as well as Microsoft's TPM-based authenticator). Most passkeys are synced across devices within the same ecosystem. For instance, a passkey created on an iPhone will typically sync to the user’s iPad and MacBook.

Third-party password managers like Dashlane, Bitwarden, and LastPass extend this capability by providing independent synchronisation frameworks, or synced keychains, enabling users to share passkeys across devices from different ecosystems. Additionally, new credential exchange protocols are making it easier to export credentials seamlessly between ecosystems, further enhancing cross-platform usability.

When users interact with third-party devices, such as work or public computers, **hybrid cross-device flows** offer a secure way to share authentication assertions between devices. These flows use BLE-enabled proximity checks without requiring device pairing. You can find more details about hybrid flows below.

In summary, passkeys are now widely available and ready for deployment. In this whitepaper, we will explore how messaging apps can leverage passkeys and FIDO protocols to implement phishing-resistant authentication, effectively preventing messenger-based phishing attacks.

## **1. Phishing-Resistant Authorisation for Mobile-to-Web Sessions**

`iOS`  `Android`  → `Web` `MacOS Desktop`

The fundamental challenge we aim to address is:

> How does the app confirm it’s communicating with the correct browser?
> 

Traditionally, apps lack the inherent capability to verify authenticity, and users are vulnerable to phishing attacks. Until recently, solving this problem was nearly impossible. Conventional approaches relied on a mix of heuristics like IP address validation, browser fingerprinting, and behavioral biometrics—essentially a trial-and-error method akin to 17th-century alchemy: apply techniques and hope the result holds.

This problem is now effectively addressed by passkeys. Passkeys uniquely answer two critical questions:

1. **Does the user possess the secret?**
2. **Is the user interacting with the correct website?**

A few years ago, the typical answers would have been “password” for the first, and “unknown” for the second. Passkeys, however, provide a robust solution: they confirm both that the user possesses the private key (secret) and is on the correct website (via origin binding). 

These features enable secure, phishing-resistant authentication, with the key innovation being that the app itself functions as the passkey server.

### **Who is this solution for?**

This solution is designed for cross-device authentication scenarios that do not depend on centralised identity infrastructure. Apps like `Signal`,  and `WhatsApp`, for example, do not maintain traditional account infrastructure. Instead, they function as brokers to establish accounts, linking devices to phone numbers. Once the account setup is complete, the broker's role in account management is minimal.

`Telegram` , `Discord` , and `Viber` have centralised authentication infrastructure, but use similar flow for easy cross-device authorisation. This flow, can be used for those flows as well.

This design ensures high levels of security and privacy but also introduces challenges for ongoing “authentication.” For such use cases, we propose that the app itself serves as the authentication server. This approach supports authenticating third-party sessions to access user accounts, where the accounts are intrinsically bound to the user’s device.

Another thing to mention is that this will work for `MacOS desktop` apps, in similar way that `iOS` app works.  See: https://developer.apple.com/documentation/authenticationservices/asauthorizationresult

### Passkey setup

The first thing that is required is for the user to register passkey with their app. This is a standard flow, that uses standard platform API.

[Setting up passkey with the app](https://youtube.com/shorts/4cDbw47oJV0)

- Android passkeys API - https://passkeys.dev/docs/reference/android/
- iOS passkeys - https://developer.apple.com/documentation/authenticationservices/asauthorizationresult

![Screenshot 2024-12-03 at 1.41.31 PM.png](White%20Paper%20Killing%20messenger%20phishing,%20with%20passk%20141cf1aba98e80ea9bcfee7353a22623/Screenshot_2024-12-03_at_1.41.31_PM.png)

Step-by-step guide:

1. **User initiates passkey setup**
2. **App generates random challenge** 
3. **App calls platform API to create new passkey**
4. **Platform checks RPID binding by fetching `.well-known/apple-app-site-association` or `assetlinks.json`**
    - The platform checks the app’s authenticity by retrieving the `apple-app-site-association` (iOS) or `assetlinks.json` (Android) file from the server. This file verifies the AppID or hash against the list of allowed applications for passkey registration.
5. **Platform request user consent**
    - *"Are you sure you want to register a passkey for 'Messenger App'?"*
6. **Once user consents, newly generated credential is returned to the app.**
7. **App decodes credential creation response, and saves it in the database.**

With this process complete, the user's account is now securely protected with passkeys.

### Authentication

Once user possess passkey, they are able to authenticate third party web session using passkeys.

The initial QR WebSocket flow, that is used by all messaging apps is still the same. However once the base tunnel is established, a passkey flow is started.

![Screenshot 2024-12-02 at 9.24.30 PM.png](White%20Paper%20Killing%20messenger%20phishing,%20with%20passk%20141cf1aba98e80ea9bcfee7353a22623/Screenshot_2024-12-02_at_9.24.30_PM.png)

Step-by-step guide:

1. **User opens the messenger web page**: `https://web.example.com`.
2. **Webpage initiates web socket session, and presents QR code that contains sessionID**
3. **User navigates in the app**:
    - Go to “App Settings” → “Add Device” → “Scan QR Code.”
4. **User scans the QR code with the app**:
    - The app extracts the `sessionID` from the QR code, and connects to the same channel as web page.

**At this stage both web app, and device are ready to communicate.**

1. **Web App sends `Init` message with simple browser info**
    1. This is simply for users benefit, to create friendly name.
2. **Messenger App presents user with a consent form:**
    1. `Are you sure you want to share a session with the “Chrome (MacOS)”`
3. **Once the user consents, app generates challenge and KEX**
    1. A standard passkey authentication request, with random, 32 byte challenge, and allow list containing known credentialID. The allow list is very important as it will enforce a specific credential response, and help with UX.
    2. Session KEX, with ECDH for example, `kexMessenger`.
4. **Messaging app sends passkey request, and KEX to the Web Session**
5. **Web Session generates `kexClient` and attaches it to the challenge, to have is signed.**
    1. For example: `challenge.kex`
    2. The reason why we want to do this, is to prevent malicious Web Socket server from spoofing KEX.
6. **Web Session calls `navigator.credentials.get` with received passkey request.**
7. **User provides consent, by scanning fingerprint, face, or typing system pin.**
8. **The resulting assertion is the returned back to the messenger app.**
9. **Messenger app validates assertion:**
    1. Checking signature, and counter
    2. Checking origin, and so preventing phishing
    3. Extracting challenge, and checking  that it contains sent random challenge.
    4. Extracting `kexMessenger` from the challenge
10. **Once validation had succeeded, a session KEX key is derived.**
11. **Messaging app generates newly created authorisation token, or long term shared encryption key, etc, etc. It is then encrypts that information with session key, and sends it to the Web App.**
12. **Web App derives session key, and decrypts payload.** 

**A new, secure, cross-device, phishing resistant tunnel, is established!**

### Demos

If user has their devices synced, as so synced passkeys, they will have the best, seamless flow.

[Passkeys Mobile-To-Web Flow](https://www.youtube.com/shorts/_QFMeFQFl8U)

If user does not have their devices synced, or they wish to login with their work laptop for example, they would have additional, passkeys hybrid flow.

[Passkeys Mobile-To-Web Hybrid Flow](https://www.youtube.com/shorts/14GGDook17M)

[https://github.com/DaryaScam/WebDemo](https://github.com/DaryaScam/WebDemo)

[https://github.com/DaryaScam/iOSDemoApp](https://github.com/DaryaScam/iOSDemoApp)

### Small security review

This flow addresses three key security concerns:

1. **Does the user control the device they are sharing with?**
    
    Yes. By logging in with a passkey, the user demonstrates control over the device. This is possible either because the passkey is synced to the device or because the user completed a secure cross-device hybrid flow. Additionally, the valid assertion provided during login proves ownership of the private key.
    
2. **Is the user logging into the expected website, or are they being phished?**
    
    Yes. Passkeys enforce origin binding, ensuring that the user is interacting with the intended domain. The messenger app can verify that the user is logging into the expected domain, and the user cannot initiate login on a malicious site due to passkeys enforcing RPID and origin requirements. Furthermore, passkeys operate exclusively over TLS, providing additional protection against phishing attempts.
    
3. **Can information be protected from tampering by a malicious WebSocket server?**
    
    Yes. By including shareable information as part of the challenge, the response information (such as key exchange data) is cryptographically protected. This ensures that the integrity of the web session is maintained, preventing tampering.
    

### Other considerations

This flow enables phishing-resistant authentication and, in the short term, can be used for app login through an app redirect. The app generates a URL for the user to authenticate and, once the process is complete, redirects back to the app. While there are some security limitations—such as the possibility of a malicious app intercepting thwe result URL—this risk is significantly lower compared to standard web phishing. Additionally, incorporating an encryption challenge in the request URL can enhance security by encrypting the result before it is sent to the callback URL.

## **2. Phishing-Resistant Authorisation for Mobile-to-Desktop Sessions**

`iOS` `iPadOS` `Android`  → `Windows` `MacOS` `Linux`

Desktop apps have unique limitations. Generally they do not have access to the platform authentication functionality, such as browsers would, even though they share all the similar core functionality. This means that we can not be using browser platform APIs to authenticate user, and thus prove their proximity. To solve this issue, we are proposing using CTAP2 Hybrid transport for sharing long term access keys. This flow would use underlying hybrid architecture, but simply use raw json payload exchange, instead of running full passkeys auth.

If we review Diagram 1, we can see that phishing is happening during the QR code scanning phase, and so this is where we can make a difference by adding Passkeys Hybrid transport, and use passkeys for phishing resistance.

![Diagram 6, Phishing happens here.](White%20Paper%20Killing%20messenger%20phishing,%20with%20passk%20141cf1aba98e80ea9bcfee7353a22623/Screenshot_2024-11-18_at_3.11.33_PM.png)

Diagram 6, Phishing happens here.

### Understanding Hybrid transport

Traditional CTAP protocols depend on direct end-to-end communication using USB, NFC, or BLE stacks.

However, this approach introduces significant friction, requiring users to either plug in a device, tap an NFC scanner, or go through the slow and often cumbersome BLE pairing process. This makes the experience tedious and inconvenient.

To address these issues, in 2019, the FIDO2 Technical Working Group (TWG) proposed a new approach initially called “Cloud Assisted Bluetooth,” which has since been renamed to "hybrid transport" in recent revisions.

In essence, the browser displays a QR challenge, and the device responds by broadcasting a BLE advertisement containing an encrypted response to the challenge. The browser reads this advertisement—without requiring any pairing—and decrypts the response. This decrypted data includes the information needed to connect to a shared WebSocket server, enabling the exchange of actual FIDO payloads.

![Diagram 4, Simplified hybrid flow](White%20Paper%20Killing%20messenger%20phishing,%20with%20passk%20141cf1aba98e80ea9bcfee7353a22623/CableNutshell.drawio.png)

Diagram 4, Simplified hybrid flow

![Diagram 5, Simplified hybrid flow, sequence diagram](White%20Paper%20Killing%20messenger%20phishing,%20with%20passk%20141cf1aba98e80ea9bcfee7353a22623/Screenshot_2024-11-18_at_3.00.44_PM.png)

Diagram 5, Simplified hybrid flow, sequence diagram

The full, and detailed algorithm can be found in the recent Review Draft of CTAP2.2 standard, section **11.5.1. QR-initiated Transactions (Hybrid Transports)**

[Client to Authenticator Protocol (CTAP)](https://fidoalliance.org/specs/fido-v2.2-rd-20241003/fido-client-to-authenticator-protocol-v2.2-rd-20241003.html#hybrid-qr-initiated)

Now that we have all pieces, we can start talking about using it to protect cross device sessions sharing. 

### Proximity-checked cross device secret sharing

![Screenshot 2024-12-17 at 8.54.20 PM.png](White%20Paper%20Killing%20messenger%20phishing,%20with%20passk%20141cf1aba98e80ea9bcfee7353a22623/Screenshot_2024-12-17_at_8.54.20_PM.png)

### Step-by-Step Guide

1. **User opens the Messenger desktop app.**
    - The app generates a hybrid QR code challenge and displays it to the user.
2. **User navigates to settings in the mobile app:**
    - Go to **App Settings** → **Add Device** → **Scan QR Code.**
3. **The mobile app computes a response to the QR challenge** and sends it to the desktop app via BLE advertisement.
4. **Simultaneously, the mobile app connects to the computed WebSocket server URL** and waits for a response.
5. **The desktop app scans for BLE advertisements** until it detects the expected `serviceUuid`.
    - Once found, it reads the `serviceData` and decodes it.
6. **The desktop app validates the mobile app’s response**, computes the WebSocket URL, and establishes a connection.

**Secure Tunnel Establishment**

1. **The desktop app initiates a `Noise` handshake** using the derived pre-shared key (PSK).
2. **The mobile app completes the `Noise` handshake** and sends the result back to the desktop app.

At this point, both devices are securely connected via a tunnel.

**User Authentication**

1. **The desktop app sends an authorization request** to the mobile app.
2. **The mobile app prompts the user for consent.**
    - Once consent is given, the mobile app generates a new session key for the desktop app.
3. **The mobile app sends the session key** to the desktop app.

**The user is now authenticated on the desktop app.**

Once this flow is complete, the web app and mobile app establish a stable, secure, and phishing-resistant connection, maintaining a seamless user experience.

### Dealing with iOS

For some magical reason, Apple does not allow `serviceData` to be included in Bluetooth advertisements. This might seem like it prevents the implementation of a Hybrid client... or does it?

We only need 20 bytes of data for the advertisement, which fits well within the 29-byte advertising limit for both iOS and Android. By prefixing the data with `0xf1d0c7a4`, we can create a 24-byte payload—enough to include three `serviceUuids`: one long and two short.

[ — 16 byte uuid — ] [ — 4 byte uuid — ] [ — 4 byte uuid — ]

```jsx
resultPeripheral {
    localName: 'Hybrid-ish Device',
    serviceUuids: [ 'f1d0c7a44f070490e1b8d530dfca2adc', 'dcd4c34d', 'fdc013a1' ]
}
```

This is enough to perform successful hybrid flow, and has all the same security properties.

Note: Dave Smith wrote an amazing article on Bluetooth advertising, which was fundamental in dealing with many of the issues. I highly recommend it https://wiresareobsolete.com/2016/01/bluetooth-uuids-and-cross-platform-advertisements/

[Passkeys Hybrid Transport for Mobile-To-Desktop app flow](https://www.youtube.com/shorts/Fk-1IZGM70w)

[https://github.com/DaryaScam/WebDemo](https://github.com/DaryaScam/WebDemo)

[https://github.com/DaryaScam/iOSDemoApp](https://github.com/DaryaScam/iOSDemoApp)

[https://github.com/DaryaScam/WebSocketServer](https://github.com/DaryaScam/WebSocketServer)

## 3. **Phishing-Resistant Authentication for Web**

`iOS` `iPadOS` `Android` `Windows` `MacOS` `Linux` → `Web`

For messaging apps that user centralised authentication, such as `Discord`, and `Viber` a general passkey authentication shall be sufficient. For that we can perform simple WebAuthn `autofill` , or passwordless authentication with passkeys.

![Screenshot 2024-12-17 at 11.19.12 PM.png](White%20Paper%20Killing%20messenger%20phishing,%20with%20passk%20141cf1aba98e80ea9bcfee7353a22623/Screenshot_2024-12-17_at_11.19.12_PM.png)

### Step-by-Step Guide for Passkey Authentication

**1. User Initiates Login**

- **Action:** The user opens the website.
- **System Process:** The website communicates with the backend by sending a request to `/assertion/options\n?mode=usernameless`.

**2. Autofill Flow (If Autofill is Triggered)**

- The user presses the username field and selects an autofill option.
- The browser prompts the user for consent:**"[CONSENT] Do you want to log in to this site?"**

**3. Username Flow (If Manual Username Entry is Used)**

- The user manually enters their username and presses "Enter."
- The website cancels any active autofill flows to avoid conflicts.
- The website communicates with the backend, and fetching challenge username specific challenge `/assertion/options\n?mode=username`.
- The browser prompts the user for consent:**"[CONSENT] Do you want to log in to this site?"**

**4. Final Authentication**

- The website sends the user's assertion data to the backend by calling `/assertion/result`.
- The backend processes the request and confirms a successful login.
- The user is logged in to the website.

[Passkey Web Login Demo](https://youtu.be/LJZLiiIhR30)

[https://github.com/DaryaScam/WebDemo](https://github.com/DaryaScam/WebDemo)

## 4. Messenger app recovery using passkeys and PRF extension

`iOS` `Android`

Account recovery is a common challenge for messaging apps. For example, **WhatsApp** frequently prompts users to enable backups to Google Drive or Dropbox. While these backups may seem convenient, they pose significant privacy risks, as attackers gaining access to the backup could read all the messages. Additionally, such backups do not restore the account identity itself—users may recover messages but will still need to create a new account instance.

This creates several issues related to account security, recoverability, and privacy.

However, the recent addition of the `PRF` extension to the **WebAuthn API** offers a promising solution. It enables the use of passkeys to derive encryption keys from fixed salts in an authorized and secure way. Messaging apps can leverage this extension to generate a passkey-bound encryption key, allowing them to create an encrypted backup of the user's actual identity.

These encrypted identity backups can then be stored in the user’s preferred location (e.g., cloud storage) or even with the messaging app itself as an opaque payload, ensuring privacy and security.

Before exploring this approach further, let’s first examine how identities currently work in messaging apps like **WhatsApp** and **Signal**. In essence, these apps do not use centralised account systems. Instead, the account resides on the user’s device, with the messenger infrastructure linking the phone number to the device's account key.

![Screenshot 2024-12-13 at 9.01.03 PM.png](White%20Paper%20Killing%20messenger%20phishing,%20with%20passk%20141cf1aba98e80ea9bcfee7353a22623/Screenshot_2024-12-13_at_9.01.03_PM.png)

### Registering mobile example

1. **User inputs their phone number.**
2. **The phone generates a private/public key pair.**
3. **The phone starts the binding process** by sending the broker server the phone number and the public key.
4. **The broker server sends an SMS code** to the specified phone number.
5. **The user enters the received SMS code** and submits it back to the broker service.
6. **The broker service verifies the SMS code, hashes the phone number,** and stores the public key indexed by the hashed phone number.

Once user is registered, user may wish to enable backup for their account, and passkeys can do just that using PRF extension.

![Screenshot 2024-12-17 at 9.58.16 PM.png](White%20Paper%20Killing%20messenger%20phishing,%20with%20passk%20141cf1aba98e80ea9bcfee7353a22623/Screenshot_2024-12-17_at_9.58.16_PM.png)

### Step-by-Step Guide for Backup Process

1. **Enable Backup in Mobile App**
    - Enter backup PIN or Password.
2. **Obtain Challenge from Backup Bucket**
    - The mobile app communicates with the Messenger Backup Bucket to request a challenge, a random string used to perform challenge response check, and protect against replay attack.
3. **Compute Salt in Mobile App**
    - Compute `recoverySalt` using the formula:`HMAC(HASH(Normalized phone number), HASH(PIN or Password))`.
4. **Generate Passkey Assertion**
    - The mobile app generates a passkey assertion with the `PRF` (Pseudorandom Function) extension, and `prf.salt1` set to `recoverySalt`
5. **User Consent**
    - **Prompt**: The user provides consent to proceed.
6. **Extract PRF Secret and Derive Keys**
    - Extract the PRF secret.
    - Derive three 32-byte keys: `idk` (Identity Key), `mack` (Message Authentication Code Key), `enck` (Encryption Key)
7. **Serialize App Data**
    - Serialise the app identity, including app private key, messages, and optionally files, etc
8. **Encrypt and Secure Data**
    - Encrypt-then-MAC using `enck` and `mack`.
    - Derive the recovery index using the formula:`HMAC(idk, HASH(credId))`.
9. **Sign Encrypted Payload**
    - Sign the encrypted payload, and x962 passkey public key with app private key
10. **Send Payload to Messenger Backup Bucket**
    - The mobile app sends asserti the signed payload to the Messenger Backup Bucket.
11. **Validate App and Passkey**
    - Validate that the app's public key exists in the Messenger Broker.
    - Validate the AppKey signature.
    - Validate the passkey signature against signed payload.
    - (Optional) Validate device app attestation, to prevent enumeration, and malicious app access.
12. **Save Encrypted Blob**
    - The Messenger Backup Bucket saves the encrypted blob.
13. **Confirm Backup Success**
    - The Messenger Backup Bucket sends an "OK" confirmation back to the mobile app.

Once backup is enabled user is able to recover their account in case of loss.

The next diagram is describing how to do 

![Screenshot 2024-12-17 at 10.23.41 PM.png](White%20Paper%20Killing%20messenger%20phishing,%20with%20passk%20141cf1aba98e80ea9bcfee7353a22623/Screenshot_2024-12-17_at_10.23.41_PM.png)

### Step-by-Step Guide: Recovering Messenger Account with Passkey and PRF

1. **Enter Phone Number and PIN/Password**
    - The user enters their phone number and PIN or password into the mobile app.
2. **Obtain Challenge**
    - The mobile app communicates with the Messenger Backup Bucket to obtain a recovery challenge.
3. **Compute Salt in Mobile App**
    - Compute `recoverySalt` using the formula:`HMAC(HASH(Normalized phone number), HASH(PIN or Password))`.
4. **Generate Passkey Assertion**
    - The mobile app generates a passkey assertion with the `PRF` (Pseudorandom Function) extension, and `prf.salt1` set to `recoverySalt`
5. **User Consent**
    - The user provides consent to proceed with the recovery process.
6. **Extract PRF Secret and Derive Keys**
    - Extract the PRF secret.
    - Derive three 32-byte keys: `idk` (Identity Key), `mack` (Message Authentication Code Key), `enck` (Encryption Key)
7. **Derive Recovery Index**
    - The mobile app derives the recovery index (`rid`) using the formula:`HMAC(idk, HASH(credId))`.
8. **Send Recovery Request**
    - The mobile app sends the signed payload to the Messenger Backup Bucket at the endpoint `/blob/${rid}`.
9. **Validate Request**
    - The Messenger Backup Bucket checks if a blob exists for the provided recovery index.
    - It the validates the passkey signature.
    - If either fails a generic error must be returned to prevent blob enumeration
    - (Optional) Validate device app attestation, to prevent enumeration, and malicious app access.
10. **Retrieve Backup Blob**
    - If validation succeeds, the Messenger Backup Bucket returns the encrypted blob to the mobile app.
11. **Decrypt Backup Blob**
    - The mobile app authenticates and decrypts the blob using:
        - `mack` for message authentication.
        - `enck` for decryption.
12. **Recovery Success**
    - The mobile app informs the user that account recovery was successful.

This process ensures secure account recovery while maintaining the integrity and privacy of the user's data.

### Security and privacy notes

> **Phone number + PIN HMAC? Why**
> 

This approach enforces rate limiting. Even if an attacker compromises the endpoint and gains the ability to call the WebAuthn API, they would still require explicit user consent for every authentication attempt.

> **Messenger does not know which blob belong to whom.**
> 

The actual data storage exposes absolute minimum, even to extend of not containing passkey credential ID. App must derive storage location using user input information, such as phone number, and pin, as well as credential information such as credential identifier. The payload itself only contain opaque public key that reveals no information about the user, or their authenticator.

> **Device attestation**
> 

For all recovery endpoints, we recommend incorporating app-device attestation mechanisms, such as Apple’s `App Attest` or Google’s `Play Integrity API`, to provide an additional layer of security, and enforce better access control.

> **Other recovery methods**
> 

This method relies entirely on passkeys, which means the user must maintain access to their passkey. However, users may delete their passkey or lose access to their keychain account. In such cases, the messenger could implement an additional backup method, such as a password with a BIP39-encoded index or an index reference, stored similarly to Bitcoin seed phrases. Alternative methods should also be explored and evaluated.

### Notes and suggestions

> **Secure External Backups**
> 

Messaging apps could prioritize giving users the option to store their backups in **user-chosen external locations**. By offering a tool that decrypts the backup blob using a secure backup key, users could independently review and manage their backups without relying on the app. This approach enhances user control, privacy, and flexibility.

> **Optional Paid Storage Plans**
> 

For those who prefer a simpler solution, messaging apps could provide **optional paid storage plans**. While basic message backups require minimal space, full backups—including photos, videos, and files—can be storage-intensive. Paid plans would cater to users who want the convenience of managing larger backups directly within the app.

## Other suggested improvements

> **Add “Disable All Other Sessions”**
> 

Currently it is quiet cumbersome to disable other active web sessions. Users need to jump through multiple menus, and frustratingly search for delete button.

We propose two changes to existing UI.

1. One button kill all “Terminate All Other Sessions” - Allows users to quickly remove all enabled accesses.

![An example from Telegram UI](White%20Paper%20Killing%20messenger%20phishing,%20with%20passk%20141cf1aba98e80ea9bcfee7353a22623/Screenshot_2024-12-03_at_12.59.06_PM.png)

An example from Telegram UI

1. Add same page session deletion. Current, for example Whatsapp, multi-menu process is frictionous. Same page, simple delete button, or system standard slide left, should simply the process and alleviate stress.

  

![Telegram slide LEFT to terminate session. ](White%20Paper%20Killing%20messenger%20phishing,%20with%20passk%20141cf1aba98e80ea9bcfee7353a22623/IMG_1792.jpg)

Telegram slide LEFT to terminate session. 

> **Auto disable old session**
> 

If a session was not used for over a 30 days, it should be disabled.

> **Add warning about session sharing**
> 

Currently only `Discord`, and `Signal` are warning users about potential harms. Messenger apps need to be more transparent about risks, and request explicit user consent before sharing access to user account.

![Discord asking consent before moving forward.](White%20Paper%20Killing%20messenger%20phishing,%20with%20passk%20141cf1aba98e80ea9bcfee7353a22623/IMG_1793.jpg)

Discord asking consent before moving forward.

![Signal being explicit about access to user information.](White%20Paper%20Killing%20messenger%20phishing,%20with%20passk%20141cf1aba98e80ea9bcfee7353a22623/IMG_1794.jpg)

Signal being explicit about access to user information.

All current (Dec 2024) user experiences can be seen in this playlist: https://www.youtube.com/playlist?list=PLC001VClMuE1pn0zFpTmMkIrUKtfV8soO

## Limitations

> **Electron does not have explicit WebAuthn API support, and general lack of application level support for passkeys**
> 

As of Electron v35, there is no proper support for passkeys in electron apps. This limits ability to secure authentication in electron apps, and require hybrid hack.

Right now in order to make passkeys work in Electron, not only your electron app needs to load app from the web, in TLS mode, it is as well needs bunch of overrides. On MacOS it is completely broken, but fortunately you can use native ASAuthorizationContoller flow, similar as we did in iOS. Discord did just that, and written a blog about it https://discord.com/blog/how-discord-modernized-mfa-with-webauthn

You can track the state of WebAuthn API in electron in issue #24573.

[https://github.com/electron/electron/issues/24573](https://github.com/electron/electron/issues/24573)

There is no easy solution to this problem though, as not all operating systems have native application identity enforcement mechanisms like MacOS, iOS and Android. This means that Android/MacOS/iOS can enforce rpid-app binding via `assetlink / apple-app-site-association` mechanism. Windows and Linux lack those features, and so it is difficult to figure out how to provide secure authentication in apps, on desktop.

> Electron BLE implementations need help
> 

Right now, to use bluetooth in your electron app you would be using `noble` library, the only functional NodeJS BLE library. The original repo was abandoned seven years ago, but thanks to community it was forked, and supported for all these years. However `noble` still needs help, and I invite you to come and contribute to this amazing project.

[https://github.com/abandonware/noble](https://github.com/abandonware/noble)

## Future

- [ ]  Finish Android demo
- [ ]  Get hybrid flow fully compliant with the specs

## Versions:

- 0.1 - First release

## Resources

**DaryaScam resources:**

- https://github.com/DaryaScam
- https://github.com/DaryaScam/Web-Demo
- https://github.com/DaryaScam/Passkeys-Hybrid-iOS-Demo
- https://github.com/DaryaScam/WebSocketServer
- https://github.com/DaryaScam/Electron-Hybrid-Host

**Useful public resources:**

- https://github.com/yackermann/awesome-webauthn - A passkey/webauthn community run list of all possible resources, demos, servers, etc.
- [https://passkeys.dev/](https://passkeys.dev/) - Amazing project on everything about passkeys.
- [https://webauthn.io/](https://webauthn.io/) - A simple passkey demo, that is useful for daily debugging.

Other:

- PRF Extension [https://w3c.github.io/webauthn/#prf-extension](https://w3c.github.io/webauthn/#prf-extension)
- Current messengers user experiences https://www.youtube.com/playlist?list=PLC001VClMuE1pn0zFpTmMkIrUKtfV8soO
- https://discord.com/blog/how-discord-modernized-mfa-with-webauthn
- https://wiresareobsolete.com/2016/01/bluetooth-uuids-and-cross-platform-advertisements/
- https://www.researchgate.net/publication/322476901_Protection_Against_Semantic_Social_Engineering_Attacks
- https://breakdev.org/evilqr-phishing/

News articles about phishing

- https://www.fortinet.com/blog/threat-research/qr-code-phishing-attempts-to-steal-credentials-from-chinese-language-users
- https://stomp.straitstimes.com/singapore-seen/now-even-scanning-qr-code-to-use-desktop-version-of-whatsapp-may-not-be-safe-thanks

# MiTransport
Secure transport for Mirror

## Info
+ Using RSA for handshake phase (pre-generated)
+ Using AES for data exchange
+ Only encrypt message sent by reliable channel

## How it work

## How to use
1. Add MiTransport.cs to NetworkManager game object.  
2. Drag current transport to MiTransport innerTransport field.  
3. Replace transport on your NetworkManager to MiTransport.

## Credits
Inspired by [Monke Transport][monke]

[monke]: <https://github.com/JesusLuvsYooh/monke> "Monke"

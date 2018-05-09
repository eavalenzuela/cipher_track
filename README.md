## cipher_track.py

A tool for figuring out what ciphers are running on a server, and comparing that against a list of 'accepted' ciphers you designate.

Intended for admins or engineers wanting to verify that the ciphers they've configured are actually the only ciphers the server is allowing, without manually sorting and comparing Qualys'(excellent) SSL Labs or ssl-enum-ciphers NSE results.

Results are limited to only live hosts running SSL-wrapped tcp services. Because this tool uses raw sockets, it *should* work for any SSL service.

It's also built to be Python2/3 cross-compatible, and use no non-native dependencies.

##### Run with:
```
python cipher_track.py <ip ranges> <ports>
python cipher_track.py 192.150.160.16/31,10.100.50.0/24 443,8080,8443
```

#### CSV output:

```
ApproveStatus,Host,Port,Cipher,CipherAvailable,Action
approved,52.9.87.221,443,ECDHE-ECDSA-AES256-GCM-SHA384,False,Add
approved,52.9.87.221,443,ECDHE-ECDSA-AES128-GCM-SHA256,False,Add
approved,52.9.87.221,443,ECDHE-ECDSA-AES256-SHA384,False,Add
approved,52.9.87.221,443,ECDHE-ECDSA-AES128-SHA256,False,Add
approved,52.9.87.221,443,ECDHE-RSA-AES256-GCM-SHA384,True,No_Change
approved,52.9.87.221,443,ECDHE-RSA-AES128-GCM-SHA256,True,No_Change
approved,52.9.87.221,443,ECDHE-RSA-AES256-SHA384,True,No_Change
approved,52.9.87.221,443,ECDHE-RSA-AES128-SHA256,True,No_Change
approved,52.9.87.221,443,ECDHE-RSA-AES256-SHA,True,No_Change
approved,52.9.87.221,443,ECDHE-RSA-AES128-SHA,True,No_Change
approved,52.9.87.221,443,ECDHE-ECDSA-CHACHA20-POLY1305,False,Add
approved,52.9.87.221,443,ECDHE-RSA-CHACHA20-POLY1305,False,Add
unapproved,52.9.87.221,443,DHE-RSA-AES256-GCM-SHA384,True,Remove
unapproved,52.9.87.221,443,DHE-RSA-AES256-SHA256,True,Remove
unapproved,52.9.87.221,443,DHE-RSA-AES256-SHA,True,Remove
unapproved,52.9.87.221,443,AES256-GCM-SHA384,True,Remove
unapproved,52.9.87.221,443,AES256-SHA256,True,Remove
unapproved,52.9.87.221,443,AES256-SHA,True,Remove
unapproved,52.9.87.221,443,DHE-RSA-AES128-GCM-SHA256,True,Remove
unapproved,52.9.87.221,443,DHE-RSA-AES128-SHA256,True,Remove
unapproved,52.9.87.221,443,DHE-RSA-AES128-SHA,True,Remove
unapproved,52.9.87.221,443,AES128-GCM-SHA256,True,Remove
unapproved,52.9.87.221,443,AES128-SHA256,True,Remove
unapproved,52.9.87.221,443,AES128-SHA,True,Remove
unapproved,52.9.87.221,443,ECDHE-RSA-DES-CBC3-SHA,True,Remove
unapproved,52.9.87.221,443,EDH-RSA-DES-CBC3-SHA,True,Remove
unapproved,52.9.87.221,443,DES-CBC3-SHA,True,Remove
approved,192.150.160.17,443,ECDHE-ECDSA-AES256-GCM-SHA384,False,Add
approved,192.150.160.17,443,ECDHE-ECDSA-AES128-GCM-SHA256,False,Add
approved,192.150.160.17,443,ECDHE-ECDSA-AES256-SHA384,False,Add
approved,192.150.160.17,443,ECDHE-ECDSA-AES128-SHA256,False,Add
approved,192.150.160.17,443,ECDHE-RSA-AES256-GCM-SHA384,True,No_Change
```

#### XML output:

```
<?xml version="1.0" ?>
 <hosts>
     <host name="52.9.87.221">
         <accepted_ciphers>
             <ECDHE-ECDSA-AES256-GCM-SHA384 port="443">False</ECDHE-ECDSA-AES256-GCM-SHA384>
             <ECDHE-ECDSA-AES128-GCM-SHA256 port="443">False</ECDHE-ECDSA-AES128-GCM-SHA256>
             <ECDHE-ECDSA-AES256-SHA384 port="443">False</ECDHE-ECDSA-AES256-SHA384>
             <ECDHE-ECDSA-AES128-SHA256 port="443">False</ECDHE-ECDSA-AES128-SHA256>
             <ECDHE-RSA-AES256-GCM-SHA384 port="443">True</ECDHE-RSA-AES256-GCM-SHA384>
             <ECDHE-RSA-AES128-GCM-SHA256 port="443">True</ECDHE-RSA-AES128-GCM-SHA256>
             <ECDHE-RSA-AES256-SHA384 port="443">True</ECDHE-RSA-AES256-SHA384>
             <ECDHE-RSA-AES128-SHA256 port="443">True</ECDHE-RSA-AES128-SHA256>
             <ECDHE-RSA-AES256-SHA port="443">True</ECDHE-RSA-AES256-SHA>
             <ECDHE-RSA-AES128-SHA port="443">True</ECDHE-RSA-AES128-SHA>
             <ECDHE-ECDSA-CHACHA20-POLY1305 port="443">False</ECDHE-ECDSA-CHACHA20-POLY1305>
             <ECDHE-RSA-CHACHA20-POLY1305 port="443">False</ECDHE-RSA-CHACHA20-POLY1305>
         </accepted_ciphers>
         <unaccepted_ciphers>
             <DHE-RSA-AES256-GCM-SHA384 port="443">True</DHE-RSA-AES256-GCM-SHA384>
             <DHE-RSA-AES256-SHA256 port="443">True</DHE-RSA-AES256-SHA256>
             <DHE-RSA-AES256-SHA port="443">True</DHE-RSA-AES256-SHA>
 ```
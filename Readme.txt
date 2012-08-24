ctjoiner Ver 1.1
-----------------

Join multible cache clusters or trackers (encrypted or plain text) in one encrypted tracker



INSTALL NOTES:

    Ubuntu Installation:


        1- Run the follwoing to install PHP5 command line:

            apt-get install php5-cli php5-mcrypt

        2- copy all files in seprate new folder

        3- Add the tracker line to csp by calling "cluster.php" and Key using in settings.xml.


CONFIGURATION NOTES:
1- tracker must include "http" part of url. 

for more info about settings and configureation, check settings.xml and Changelog.txt .


Some important security caveats:

1- it is very important to protect your cluster.php and settings.xml with .htaccess or any other way you know.
2- if you will use local cluster, it is also highly recommended to protect it with same methode you will use as above.
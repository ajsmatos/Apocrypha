

#!/bin/bash






while true; do #start daemon loop
		 
		#ENCRYPTION
		
		#ENCRYPTION USING AES 128 CBC
		DIR="./Encryption/Encrypt-AES-128-CBC" #var with the directory
		if [ "$(ls -A $DIR)" ]; then #if we can list the directory...
		     	echo "Take action $DIR is not Empty" #...the direcotory is no empty
			for file in Encryption/Encrypt-AES-128-CBC/* #for every file in the directory
				do

		                openssl rand -hex 16 > key-file.txt #generate a random 128 bit hex key to a file
				openssl rand -hex 16 > iv-file.txt  #generate a random 128 bit hex inicialization vector to a file
				key=$(cat key-file.txt) #atribuition of the content of key file to a var key
				iv=$(cat iv-file.txt) #atribuition of the content of iv file to a var iv
				
				openssl enc -aes-128-cbc -e -in $file -out $file.aes128cbc -K $key -iv $iv #Encrypt the file with aes 128 cbc, respective key and iv generated before  
				DIR="./Encryption/Encrypted" #change directory var to Encrypted dir
				mv key-file.txt Encryption/Encrypted #move key file to folder Encrypted
				mv iv-file.txt  Encryption/Encrypted #move iv file to folder Encrypted
				mv $file $DIR #move the original file to the Encrypted dir
				mv $file.aes128cbc $DIR #move the encrypted file to the Encrypted dir
			
				done	
	
		else #if the directory is empty
    			echo "$DIR is Empty" #echo the directory is not empty
		fi
		
		#ENCRYPTION USING AES 256 CBC
		DIR="./Encryption/Encrypt-AES-256-CBC" #var with the directory
		if [ "$(ls -A $DIR)" ]; then #if we can list the directory...
		     	echo "Take action $DIR is not Empty" #...the direcotory is no empty
			for file in Encryption/Encrypt-AES-256-CBC/* #for every file in the directory
				do

		                openssl rand -hex 32 > key-file.txt #generate a random 256 bit hex key to a file
				openssl rand -hex 16 > iv-file.txt  #generate a random 128 bit hex inicialization vector to a file
				key=$(cat key-file.txt) #atribuition of the content of key file to a var key
				iv=$(cat iv-file.txt) #atribuition of the content of iv file to a var iv
				
				openssl enc -aes-256-cbc -e -in $file -out $file.aes256cbc -K $key -iv $iv #Encrypt the file with aes 256 cbc, respective key and iv generated before  
				DIR="./Encryption/Encrypted" #change directory var to Encrypted dir
				mv key-file.txt Encryption/Encrypted #move key file to folder Encrypted
				mv iv-file.txt  Encryption/Encrypted #move iv file to folder Encrypted
				mv $file $DIR #move the original file to the Encrypted dir
				mv $file.aes256cbc $DIR #move the encrypted file to the Encrypted dir
			
				done	
	
		else #if the directory is empty
    			echo "$DIR is Empty" #echo the directory is not empty
		fi

		#ENCRYPTION USING DES CBC
		DIR="./Encryption/Encrypt-DES-CBC" #var with the directory
		if [ "$(ls -A $DIR)" ]; then #if we can list the directory...
		     	echo "Take action $DIR is not Empty" #...the direcotory is no empty
			for file in Encryption/Encrypt-DES-CBC/* #for every file in the directory
				do

		                openssl rand -hex 7 > key-file.txt #generate a random 56 bit hex key to a file
				openssl rand -hex 8 > iv-file.txt  #generate a random 64 bit hex inicialization vector to a file
				key=$(cat key-file.txt) #atribuition of the content of key file to a var key
				iv=$(cat iv-file.txt) #atribuition of the content of iv file to a var iv
				
				openssl enc -des-cbc -e -in $file -out $file.descbc -K $key -iv $iv #Encrypt the file with des cbc, respective key and iv generated before  
				DIR="./Encryption/Encrypted" #change directory var to Encrypted dir
				mv key-file.txt Encryption/Encrypted #move key file to folder Encrypted
				mv iv-file.txt  Encryption/Encrypted #move iv file to folder Encrypted
				mv $file $DIR #move the original file to the Encrypted dir
				mv $file.descbc $DIR #move the encrypted file to the Encrypted dir
			
				done	
	
		else #if the directory is empty
    			echo "$DIR is Empty" #echo the directory is not empty
		fi

		#ENCRYPTION USING DES3
		DIR="./Encryption/Encrypt-DES3" #var with the directory
		if [ "$(ls -A $DIR)" ]; then #if we can list the directory...
		     	echo "Take action $DIR is not Empty" #...the direcotory is no empty
			for file in Encryption/Encrypt-DES3/* #for every file in the directory
				do

		                openssl rand -hex 21 > key-file.txt #generate a random 168 bit hex key to a file
				openssl rand -hex 8 > iv-file.txt  #generate a random 64 bit hex inicialization vector to a file
				key=$(cat key-file.txt) #atribuition of the content of key file to a var key
				iv=$(cat iv-file.txt) #atribuition of the content of iv file to a var iv
				
				openssl enc -des3 -e -in $file -out $file.des3 -K $key -iv $iv #Encrypt the file with des cbc, respective key and iv generated before  
				DIR="./Encryption/Encrypted" #change directory var to Encrypted dir
				mv key-file.txt Encryption/Encrypted #move key file to folder Encrypted
				mv iv-file.txt  Encryption/Encrypted #move iv file to folder Encrypted
				mv $file $DIR #move the original file to the Encrypted dir
				mv $file.des3 $DIR #move the encrypted file to the Encrypted dir
			
				done	
	
		else #if the directory is empty
    			echo "$DIR is Empty" #echo the directory is not empty
		fi
		

		
		#DECRYPTION

                #DECRYPTION OF AES 128 CBC
		DIR="./Decryption/Decrypt-AES-128-CBC" #var with the directory
		if [ "$(ls -A $DIR)" ]; then #if we can list the directory...
		     	echo "Take action $DIR is not Empty" #...the direcotory is no empty
			for file in Decryption/Decrypt-AES-128-CBC/* #for every file in the directory
				do

				key=$(cat ./Decryption/Decrypt-AES-128-CBC/key-file.txt) # read the content of key file to var key
				iv=$(cat ./Decryption/Decrypt-AES-128-CBC/iv-file.txt) #read the content of iv-file to var iv
				if [ "$file" != "Decryption/Decrypt-AES-128-CBC/key-file.txt" ] && [ "$file" != "Decryption/Decrypt-AES-128-CBC/iv-file.txt" ]; #if the file name is different from the key-file and the iv-file
					then
					openssl enc -aes-128-cbc -d -in $file -out $file.dec -K $key -iv $iv #decrypt the file with the key and iv provided before
					DIR="./Decryption/Decrypted" #change directory var do Decrypted dir
					mv Decryption/Decrypt-AES-128-CBC/iv-file.txt $DIR #move iv-file to folder Decrypted
					mv Decryption/Decrypt-AES-128-CBC/key-file.txt $DIR #move key-file to folder decrypted
					mv $file $DIR #move file to folder Decrypted
					mv $file.dec $DIR #move decripted file to folder Decrypted		 
				fi
			done	
	
		else #if the directory is empty
    			echo "$DIR is Empty" #echo the directory is not empty
		fi

		#DECRYPTION OF AES 256 CBC
		DIR="./Decryption/Decrypt-AES-256-CBC" #var with the directory
		if [ "$(ls -A $DIR)" ]; then #if we can list the directory...
		     	echo "Take action $DIR is not Empty" #...the direcotory is no empty
			for file in Decryption/Decrypt-AES-256-CBC/* #for every file in the directory
				do

				key=$(cat ./Decryption/Decrypt-AES-256-CBC/key-file.txt) # read the content of key file to var key
				iv=$(cat ./Decryption/Decrypt-AES-256-CBC/iv-file.txt) #read the content of iv-file to var iv
				if [ "$file" != "Decryption/Decrypt-AES-256-CBC/key-file.txt" ] && [ "$file" != "Decryption/Decrypt-AES-256-CBC/iv-file.txt" ]; #if the file name is different from the key-file and the iv-file
					then
					openssl enc -aes-256-cbc -d -in $file -out $file.dec -K $key -iv $iv #decrypt the file with the key and iv provided before
					DIR="./Decryption/Decrypted" #change directory var do Decrypted dir
					mv Decryption/Decrypt-AES-256-CBC/iv-file.txt $DIR #move iv-file to folder Decrypted
					mv Decryption/Decrypt-AES-256-CBC/key-file.txt $DIR #move key-file to folder decrypted
					mv $file $DIR #move file to folder Decrypted
					mv $file.dec $DIR #move decripted file to folder Decrypted		 
				fi
			done	
	
		else #if the directory is empty
    			echo "$DIR is Empty" #echo the directory is not empty
		fi

		#DECRYPTION OF DES CBC
		DIR="./Decryption/Decrypt-DES-CBC" #var with the directory
		if [ "$(ls -A $DIR)" ]; then #if we can list the directory...
		     	echo "Take action $DIR is not Empty" #...the direcotory is no empty
			for file in Decryption/Decrypt-DES-CBC/* #for every file in the directory
				do

				key=$(cat ./Decryption/Decrypt-DES-CBC/key-file.txt) # read the content of key file to var key
				iv=$(cat ./Decryption/Decrypt-DES-CBC/iv-file.txt) #read the content of iv-file to var iv
				if [ "$file" != "Decryption/Decrypt-DES-CBC/key-file.txt" ] && [ "$file" != "Decryption/Decrypt-DES-CBC/iv-file.txt" ]; #if the file name is different from the key-file and the iv-file
					then
					openssl enc -des-cbc -d -in $file -out $file.dec -K $key -iv $iv #decrypt the file with the key and iv provided before
					DIR="./Decryption/Decrypted" #change directory var do Decrypted dir
					mv Decryption/Decrypt-DES-CBC/iv-file.txt $DIR #move iv-file to folder Decrypted
					mv Decryption/Decrypt-DES-CBC/key-file.txt $DIR #move key-file to folder decrypted
					mv $file $DIR #move file to folder Decrypted
					mv $file.dec $DIR #move decripted file to folder Decrypted		 
				fi
			done	
	
		else #if the directory is empty
    			echo "$DIR is Empty" #echo the directory is not empty
		fi

		#DECRYPTION OF DES3
		DIR="./Decryption/Decrypt-DES3" #var with the directory
		if [ "$(ls -A $DIR)" ]; then #if we can list the directory...
		     	echo "Take action $DIR is not Empty" #...the direcotory is no empty
			for file in Decryption/Decrypt-DES3/* #for every file in the directory
				do

				key=$(cat ./Decryption/Decrypt-DES3/key-file.txt) # read the content of key file to var key
				iv=$(cat ./Decryption/Decrypt-DES3/iv-file.txt) #read the content of iv-file to var iv
				if [ "$file" != "Decryption/Decrypt-DES3/key-file.txt" ] && [ "$file" != "Decryption/Decrypt-DES3/iv-file.txt" ]; #if the file name is different from the key-file and the iv-file
					then
					openssl enc -des3 -d -in $file -out $file.dec -K $key -iv $iv #decrypt the file with the key and iv provided before
					DIR="./Decryption/Decrypted" #change directory var do Decrypted dir
					mv Decryption/Decrypt-DES3/iv-file.txt $DIR #move iv-file to folder Decrypted
					mv Decryption/Decrypt-DES3/key-file.txt $DIR #move key-file to folder decrypted
					mv $file $DIR #move file to folder Decrypted
					mv $file.dec $DIR #move decripted file to folder Decrypted		 
				fi
			done	
	
		else #if the directory is empty
    			echo "$DIR is Empty" #echo the directory is not empty
		fi

		#DIGEST
			
		#DIGEST WITH MD5
		DIR="./Digest/md5" #var with the directory
		if [ "$(ls -A $DIR)" ]; then #if we can list the directory...
		     	echo "Take action $DIR is not Empty" #...the direcotory is no empty
			for file in Digest/md5/* #for the file in the directory
				do
				
				openssl dgst -md5 $file > $file.md5 #create new file.md5 with the calculated md5 hash value from the file
				DIR="./Digest/Hashes" #change directory var Hashes Dir
				mv $file.md5 $DIR #move the file.md5 to the Hashes dir
				mv $file $DIR #move original file to Hashes dir
				
			


				done	
	
		else #if the directory is empty
    			echo "$DIR is Empty" #echo the directory is not empty
		fi

		#DIGEST WITH SHA1
		DIR="./Digest/sha1" #var with the directory
		if [ "$(ls -A $DIR)" ]; then #if we can list the directory...
		     	echo "Take action $DIR is not Empty" #...the direcotory is no empty
			for file in Digest/sha1/* #for the file in the directory
				do
				
				openssl dgst -sha1 $file > $file.sha1 #create new file.sha1 with the calculated sha1 hash value from the file
				DIR="./Digest/Hashes" #change directory var Hashes Dir
				mv $file.sha1 $DIR #move the file.sha1 to the Hashes dir
				mv $file $DIR #move original file to Hashes dir
				
			


				done	
	
		else #if the directory is empty
    			echo "$DIR is Empty" #echo the directory is not empty
		fi


		#DIGEST WITH SHA256
		DIR="./Digest/sha256" #var with the directory
		if [ "$(ls -A $DIR)" ]; then #if we can list the directory...
		     	echo "Take action $DIR is not Empty" #...the direcotory is no empty
			for file in Digest/sha256/* #for the file in the directory
				do
				
				openssl dgst -sha256 $file > $file.sha256 #create new file.sha256 with the calculated sha1 hash value from the file
				DIR="./Digest/Hashes" #change directory var Hashes Dir
				mv $file.sha256 $DIR #move the file.sha256 to the Hashes dir
				mv $file $DIR #move original file to Hashes dir
				
			


				done	
	
		else #if the directory is empty
    			echo "$DIR is Empty" #echo the directory is not empty
		fi

		#DIGEST WITH SHA512
		DIR="./Digest/sha512" #var with the directory
		if [ "$(ls -A $DIR)" ]; then #if we can list the directory...
		     	echo "Take action $DIR is not Empty" #...the direcotory is no empty
			for file in Digest/sha512/* #for the file in the directory
				do
				
				openssl dgst -sha512 $file > $file.sha512 #create new file.sha512 with the calculated sha1 hash value from the file
				DIR="./Digest/Hashes" #change directory var Hashes Dir
				mv $file.sha512 $DIR #move the file.sha256 to the Hashes dir
				mv $file $DIR #move original file to Hashes dir
				
			


				done	
	
		else #if the directory is empty
    			echo "$DIR is Empty" #echo the directory is not empty
		fi
		
		
		#INTEGRITY CHECK MD5

		DIR="./IntegrityCheck/Integrity-md5" #var with the directory
		if [ "$(ls -A $DIR)" ]; then #if we can list the directory...
		     	echo "$DIR is not Empty" #...the direcotory is not empty
			for file in IntegrityCheck/Integrity-md5/* #for the file in the directory
				do
					
					if [ "$file" != "IntegrityCheck/Integrity-md5/HashToCheck.md5" ]; #if the file is different of the hash to check
					then
						openssl dgst -md5 $file |cut -f 2 -d " "  > tmphash1.txt # calculates and cuts the ONLY md5 hash value of the file to the a temporary file nº1
						cut -f 2 -d " " IntegrityCheck/Integrity-md5/HashToCheck.md5 > tmphash2.txt #cuts the hash to check value to a temporary file nº2
						
						
						if [ "$(cat tmphash1.txt)" = "$(cat tmphash2.txt)" ] #if the cat of the 2 temporary files are equal
						then
							
							rm tmphash1.txt #removes temporary file number one
							rm tmphash2.txt #removes temporary file number two
							DIR="./IntegrityCheck/Int-Valid" #changes the directory var to Int-Valid Folder
							mv $file $DIR #moves the original file to Int-Valid Folder
							mv IntegrityCheck/Integrity-md5/HashToCheck.md5 $DIR #moves the hash to check to Int-Valid folder
							
				        		
						else #if not
							
							rm tmphash1.txt #removes temporary file number one
							rm tmphash2.txt #removes temporary file number two
							DIR="./IntegrityCheck/Int-Not-Valid" #changes the directory var to Int-Not-Valid Folder
							mv $file $DIR #moves the original file to Int-Not-Valid Folder
							mv IntegrityCheck/Integrity-md5/HashToCheck.md5 $DIR #moves the hash to check to Int-Not-Valid folder
				        		

						fi
						
						

					fi
				done	
	
		else #if the directory is empty
    			echo "$DIR is Empty" #echo the directory is not empty
		fi
		
		#INTEGRITY CHECK SHA1

		DIR="./IntegrityCheck/Integrity-sha1" #var with the directory
		if [ "$(ls -A $DIR)" ]; then #if we can list the directory...
		     	echo "$DIR is not Empty" #...the direcotory is not empty
			for file in IntegrityCheck/Integrity-sha1/* #for the file in the directory
				do
					
					if [ "$file" != "IntegrityCheck/Integrity-sha1/HashToCheck.sha1" ]; #if the file is different of the hash to check
					then
						openssl dgst -sha1 $file |cut -f 2 -d " "  > tmphash1.txt # calculates and cuts the ONLY md5 hash value of the file to the a temporary file nº1
						cut -f 2 -d " " IntegrityCheck/Integrity-sha1/HashToCheck.sha1 > tmphash2.txt #cuts the hash to check value to a temporary file nº2
						
						
						if [ "$(cat tmphash1.txt)" = "$(cat tmphash2.txt)" ] #if the cat of the 2 temporary files are equal
						then
							
							rm tmphash1.txt #removes temporary file number one
							rm tmphash2.txt #removes temporary file number two
							DIR="./IntegrityCheck/Int-Valid" #changes the directory var to Int-Valid Folder
							mv $file $DIR #moves the original file to Int-Valid Folder
							mv IntegrityCheck/Integrity-sha1/HashToCheck.sha1 $DIR #moves the hash to check to Int-Valid folder
							
				        		
						else #if not
							
							rm tmphash1.txt #removes temporary file number one
							rm tmphash2.txt #removes temporary file number two
							DIR="./IntegrityCheck/Int-Not-Valid" #changes the directory var to Int-Not-Valid Folder
							mv $file $DIR #moves the original file to Int-Not-Valid Folder
							mv IntegrityCheck/Integrity-sha1/HashToCheck.sha1 $DIR #moves the hash to check to Int-Not-Valid folder
				        		

						fi
						
						

					fi
				done	
	
		else #if the directory is empty
    			echo "$DIR is Empty" #echo the directory is not empty
		fi

		#SIGNING DOCUMENTS WITH RSA KEYS
		
		DIR="./Signatures/Signing/Sign" #var with the directory
		if [ "$(ls -A $DIR)" ]; then #if we can list the directory...
		     	echo "$DIR is not Empty" #...the direcotory is not empty
			for file in Signatures/Signing/Sign/* #for the file in the directory
				do
					
					if [ "$file" != "Signatures/Signing/Sign/private-key-file.pem" ]; #if the file name is different from the private key
					then
						openssl dgst -sha256 -sign Signatures/Signing/Sign/private-key-file.pem $file > $file.sig #signs the file with the private key and creates the signature file
						DIR="./Signatures/Signing/Signed" #change directory var to Signed folder

						mv $file.sig $DIR #move signature file to Signed Folder
						mv Signatures/Signing/Sign/private-key-file.pem $DIR #move private key to Signed Folder
						mv $file $DIR #move the file to Signed Folder
				        	
						

					fi
				done	
	
		else #if the directory is empty
    			echo "$DIR is Empty" #echo the directory is not empty
		fi
		
		#VERIFY RSA SIGNTURE

		DIR="./Signatures/Verifying/Verify" #var with the directory
		if [ "$(ls -A $DIR)" ]; then #if we can list the directory...
		     	echo "$DIR is not Empty" #...the direcotory is not empty
			for file in Signatures/Verifying/Verify/* #for the file in the directory
				do
					
					if [ "$file" != "Signatures/Verifying/Verify/public-key-file.pem" ] && [ "$file" != "Signatures/Verifying/Verify/signature.sig" ]; # if the file is different from the public key file and the signature file
					then
						openssl dgst -sha256 -verify Signatures/Verifying/Verify/public-key-file.pem -signature Signatures/Verifying/Verify/signature.sig $file > tmp.txt #verify the signature file, using the public key and the original file. Writes the output of the command into a a temporary file
						
						mv tmp.txt $DIR #moves the temporary file to the directory
						if [ "$(cat Signatures/Verifying/Verify/tmp.txt)" = "Verified OK" ] #if the content of the file is "Verified OK"
						then
							rm Signatures/Verifying/Verify/tmp.txt #remove the temporary file
							DIR="Signatures/Verifying/Valid-Sign" #change directory var to Valid-Sign folder
							mv $file $DIR #move file to Valid-Sign folder
							mv Signatures/Verifying/Verify/public-key-file.pem $DIR #move public key to Valid-Sign Folder
							mv Signatures/Verifying/Verify/signature.sig $DIR #move signature file to Valid-Sign Folder
				        		
						else 
							rm Signatures/Verifying/Verify/tmp.txt #remove the temporary file
							DIR="Signatures/Verifying/Not-Valid-Sign" # change directory var to Not-Valid-Sign
							mv $file $DIR #move file to Not-Valid-Sign folder
							mv Signatures/Verifying/Verify/public-key-file.pem $DIR #move public key to Not-Valid Sign Folder
							mv Signatures/Verifying/Verify/signature.sig $DIR # move signature file to Not-Valid Folder
				        		

						fi
						
						

					fi
				done	
	
		else #if the directory is empty
    			echo "$DIR is Empty" #echo the directory is not empty
		fi
	


		#HMAC
		
		#HMAC CALCULATION
		DIR="./HMAC/Calculate-HMAC/Calculate" #var with the directory
		if [ "$(ls -A $DIR)" ]; then #if we can list the directory...
		     	echo "Take action $DIR is not Empty" #...the direcotory is no empty
			for file in HMAC/Calculate-HMAC/Calculate/* #for the file in the directory
				do
				
				openssl dgst -sha1 $file |cut -f 2 -d " " > $file.sha1 #create new file.sha1 with the calculated sha1 hash value from the file, with the value cutted
				openssl rand -hex 16 > key-file.txt #generate a random 128 hex key to a file
				openssl rand -hex 16 > iv-file.txt  #generate a random 128 hex inicialization vector to a file
				key=$(cat key-file.txt) #atribuition of the content of key file to a var key
				iv=$(cat iv-file.txt) #atribuition of the content of iv file to a var iv
				
				openssl enc -aes128 -e -in $file.sha1 -out $file.mac -K $key -iv $iv #Encrypt the file.sha1 with aes128, respective key and iv generated before  

				DIR="./HMAC/Calculate-HMAC/Calculated" #change directory var Calculated dir
				mv $file.sha1 $DIR #move the file.sha1 to the Calculated dir
				mv $file.mac $DIR #move the file.mac to the Calculated dir
				mv $file $DIR #move original file to Calculated dir
				mv key-file.txt $DIR #move the key-file.txt to Calculated dir
				mv iv-file.txt $DIR #move the iv-file.txt to Calculated dir
				
			


				done	
	
		else #if the directory is empty
    			echo "$DIR is Empty" #echo the directory is not empty
		fi
		
		#HMAC VERIFICATION
		DIR="./HMAC/Verify-HMAC/Verify" #var with the directory
		if [ "$(ls -A $DIR)" ]; then #if we can list the directory...
		     	echo "Take action $DIR is not Empty" #...the direcotory is no empty
			for file in HMAC/Verify-HMAC/Verify/* #for the file in the directory
				do
				if [ "$file" != "HMAC/Verify-HMAC/Verify/key-file.txt" ] && [ "$file" != "HMAC/Verify-HMAC/Verify/iv-file.txt" ] && [ "$file" != "HMAC/Verify-HMAC/Verify/MacToCheck.mac" ]; #if the file name is different from the key-file, the iv-file, and the Mac to Check
					then

					openssl dgst -sha1 $file |cut -f 2 -d " " > $file.sha1 #create new file.sha1 with the calculated sha1 hash value from the file
					key=$(cat ./HMAC/Verify-HMAC/Verify/key-file.txt) # read the content of key file to var key
					iv=$(cat ./HMAC/Verify-HMAC/Verify/iv-file.txt) #read the content of iv-file to var iv
					openssl enc -aes128 -e -in $file.sha1 -out MacToCompare.mac -K $key -iv $iv #Encrypt the file with aes128, respective key and iv generated before
					mv MacToCompare.mac $DIR
					cat ./HMAC/Verify-HMAC/Verify/MacToCompare.mac > mac1 #cat mac to compare to a temporary file
					cat ./HMAC/Verify-HMAC/Verify/MacToCheck.mac > mac2 #cat mac to check to a temporary file
					
					if [ "$(cat mac1)" = "$(cat mac2)" ] #if the cat of the 2 temporary files are equal
						then
							echo "resultou"
							rm mac1 #remove temporary file 1
							rm mac2 #remove temporary file 2
							rm $file.sha1	#remove temporary sha1 hash value of the file
							rm ./HMAC/Verify-HMAC/Verify/MacToCompare.mac #remove mac to compare
							DIR="./HMAC/Verify-HMAC/HMAC-Valid" #change directory var HMAC-Not-Valid dir
							mv $file $DIR #move the file to the HMAC-Valid dir
							mv ./HMAC/Verify-HMAC/Verify/key-file.txt $DIR #move the key-file.txt to HMAC-Valid dir
							mv ./HMAC/Verify-HMAC/Verify/iv-file.txt $DIR #move the iv-file.txt to HMAC-Valid dir
							mv ./HMAC/Verify-HMAC/Verify/MacToCheck.mac $DIR #move mac to check to HMAC-Valid
							
						
						else
							echo "não resultou"
							rm mac1 #remove temporary file 1
							rm mac2 #remove temporary file 2
							rm $file.sha1 #remove temporary sha1 hash value of the file
							rm ./HMAC/Verify-HMAC/Verify/MacToCompare.mac #remove mac to compare
							DIR="./HMAC/Verify-HMAC/HMAC-Not-Valid" #change directory var HMAC-Not-Valid dir
							mv $file $DIR  #move the file to the HMAC-Not-Valid dir
							mv ./HMAC/Verify-HMAC/Verify/key-file.txt $DIR #move the key-file.txt to HMAC-Not-Valid dir
							mv ./HMAC/Verify-HMAC/Verify/iv-file.txt $DIR #move the iv-file.txt to HMAC-Not-Valid dir
							mv ./HMAC/Verify-HMAC/Verify/MacToCheck.mac $DIR #move mac to check to HMAC-Not-Valid dir

					fi

					
				
			
				fi

				done	
	
		else #if the directory is empty
    			echo "$DIR is Empty" #echo the directory is not empty
		fi

	        sleep 30 #sleeps the program for 30 seconds
:
done #end while loop to verify the Dir




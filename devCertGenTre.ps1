# Utility per la creazione di certificati V.2
$Versione='20200409a'

<#F.Beconcini 20200409
Identificazione dell'ambito operativo in base alla variabile d'ambiente
ENV:\Ambiente. 
Traduzione dei mesi in italiano per $Activation e $Expiration
#>


$Account= get-item "ENV:\USERNAME"
switch ($Account.Value) {
	"T000386X" {$UserName= "Beconcini"}
	"S540061X" {$UserName= "Mannoni"}
	default {$UserName= "Unknown"}
}

. (".\Library.ps1")

$FileCSVData= $args[0]
$SingleStep= $args[1]

#------------------------------------------------------------------------------
# Se non esiste il file CSV si esce con un messaggio d'errore
if (!(Test-Path $FileCSVData)) {Throw "Il file dei dati $FileCSVData non esiste"}

$CSV= Import-csv $FileCSVData
$CertCount= 0
#------------------------------------------------------------------------------
# Lettura delle variabili dal file CSV
foreach ($Certificate in $CSV) {
    $TimeStamp= Get-Date
	$MessageColour= 'Green'
	
	#------------------------------------------------------------------------------
	# Si azzera la SubCA perchè viene riutilizzato il valore non inizializzandolo 
	# per evitare la rilettura del certificato nell'elaborazione del PFX
	$SubCA= ''

    $CertCount++
    #$PerC= 100/$CSV.Count*($CertCount-1)
    #Write-Progress -Activity "Scan dei certificati" -Status "$CertCount/$($DirList.Count) certificati acquisiti" -PercentComplete $PerC

    if (!$Certificate.CN) {Throw "Errore nel file dei dati $FileCSVData non esiste il CommonName"}
    
	$Certificate.CN= $Certificate.CN.Trim()

    if ($Certificate.SAN) 
        {$MultiSAN= @($Certificate.SAN.split(';').trim())}
    else
        {$MultiSAN= @('---')} #Cast $Multisan ad un array

    if (!$Certificate.SHA) {$Certificate.SHA='SHA256'}
	
    if (!$Certificate.PassWD) {
		if (($Certificate.Ambito -eq 'Public-Produzione') -or ($Certificate.Ambito -eq 'Public-NPE'))
			{$Certificate.PassWD=[System.Web.Security.Membership]::GeneratePassword(10,0)}
		else
			{$Certificate.PassWD='12345678'}
	}

    #------------------------------------------------------------------------------
    #Diverse disposizioni a seconda dell'Ambito di sicurezza in questione
    switch ($Certificate.Ambito) {
        "Public-Produzione" {
            $NAS= "\\nassi1.local\certificati\ATTIVI\"
        }
        "Public-NPE" {
            $NAS= "\\nastf2.local\certificati\attivi\"
        }
        "Local" {
            $NAS= "\\nassi1.local\certificati\ATTIVI\"
            $Template= 'CertificateTemplate:WebServerConsorzioGMPS'
            switch ($Certificate.SHA) {
                "SHA1" {
                    $CertAuth= "SE001000456751.testfactory.copergmps\SUBMPS1-TF"
				}
                "SHA256" {
					$CertAuth= "se000000010760.sum.local\SUB01-LOCAL G2"
				}
                default {Throw "`tAlgortmo SHA $($Certificate.SHA) non valido`r`n"}
			}
		}
        "Global" {
            $NAS= "\\nassi1.local\certificati\ATTIVI\"
            $CertAuth= "se000005850760.gmps.global\SUB01-GMPS"
            $Template= 'CertificateTemplate:WebServerGMPS256'
			if ($Certificate.SHA -ne "SHA256") {Throw "`tAlgortmo SHA $($Certificate.SHA) non valido per $($Certificate.Ambiente)`r`n"}
		}
        "NPE" {
            $NAS= "\\nastf2.local\certificati\attivi\"
            $CertAuth= "SE001000456751.testfactory.copergmps\SUBMPS1-TF"
            $Template= 'CertificateTemplate:UnixComp2048'
			#if ($Certificate.SHA -ne "SHA256") {Throw "`tAlgortmo SHA $($Certificate.SHA) non valido per $($Certificate.Ambiente)`r`n"}
        }
        default {Throw "`tAmbito $($Certificate.Ambito) non valido`r`n"}
	}

	$CertificateFolder= $NAS + $Certificate.CN + '\'

    Write-Host "`n--------------------------------------------------------------------------------"
    Write-Host "$TimeStamp Elaborazione del certificato #$CertCount $($Certificate.CN)"

	#------------------------------------------------------------------------------
	# Si identifica l'ambiente operativo corrente
	$Ambiente= get-item "ENV:\Ambiente"
	switch ($Ambiente.Value) {
		'SYSPROD' {$AmbienteExe= 'PRODUZIONE'}
		'CODING' {$AmbienteExe= 'NPE'}
		'TFSTRUCT' {$AmbienteExe= 'NPE'}
		default {Throw "Non identificato l'ambiente operativo Produzione/NPE"}
	}

	#------------------------------------------------------------------------------
	# Verifica che la macchina di esecuzione sia consistente con l'ambiente operativo corrente
	if (($AmbienteExe -eq 'NPE') -and ($NAS -eq "\\nassi1.local\certificati\ATTIVI\")) {
		$MessageColour= 'Red'
		Write-Host -Foreground black -BackgroundColor $MessageColour "`tNon è possibile creare il certificato $($Certificate.CN) partendo dall'ambiente di Produzione"
		continue
	}
	elseif (($AmbienteExe -eq 'PRODUZIONE') -and ($NAS -eq "\\nastf2.local\certificati\ATTIVI\")) {
		$MessageColour= 'Red'
		Write-Host -Foreground black -BackgroundColor $MessageColour "`tNon è possibile creare il certificato $($Certificate.CN) partendo dall'ambiente NPE"
		continue
	}

	#--------------------------------------------------
	# Se non esiste si determina una nuova cartella di destinazione partendo dalla $Release=1
	$Release= 1
	if(Test-Path $CertificateFolder) {
		#--------------------------------------------------
		# Se esiste già la cartella Rn si ricava il nome della successiva
		# mettendo il suffisso di release = n+1
		while (Test-Path $($CertificateFolder + "R$Release\")) {$Release++}
	}

	if ($SingleStep -and ($SingleStep -ne 'OPT') -and ($Release -gt 0)) {$Release--}
	$FolderDestination= $CertificateFolder + "R$Release\"

	#--------------------------------------------------------------------------------
	# Si preparano le variabili per i nomi dei file
    $FileOPT= $FolderDestination + $Certificate.CN + ".OPT"	#File delle opzioni per produrre il CSR
    $FileCSR= $FolderDestination + $Certificate.CN + ".CSR"	#File Certificate Sign Request X509 PEM
    $FileCER= $FolderDestination + $Certificate.CN + ".CER"	#Certificato prodotto dalla CA
    $FileRSP= $FolderDestination + $Certificate.CN + ".rsp"	#File con le risposte della CA
    $FilePFX= $FolderDestination + $Certificate.CN + ".PFX"	#File PKCS#12 con chiave pubblica e privata
    $FTmpPUB= $FolderDestination + $Certificate.CN + "_PUB_tmp.crt"	#File temporaneo con la chiave PUBBLICA
    $FTmpPRV= $FolderDestination + $Certificate.CN + "_PRV_tmp.key"	#File temporaneo con la chiave PRIVATA
    $FilePUB= $FolderDestination + $Certificate.CN + "_PUB.CRT"	#File con la chiave PUBBLICA e KeyChain X509 PEM
    $FilePRV= $FolderDestination + $Certificate.CN + "_PRV.KEY"	#File con la chiave PRIVATA e KeyChain X509 PEM
	$FileDTL= $FolderDestination + $Certificate.CN + ".TXT"	#File di testo con i dettagli del certificato
    $FileCSV= $FolderDestination + $Certificate.CN + ".CSV"	#File CSV necessario per produrre il certificato
    $FileJKS= $FolderDestination + $Certificate.CN + ".JKS"	#File Java Key Store

	#----------------------------------------------------------------------------------------
	# Si compone il contenuto informativo per il file TXT
	$Details= "# CertGenDue v.$Versione   $TimeStamp`r`n`r`n" + `
		"Codice APM`r`n`t$($Certificate.CodiceAPM)`r`n`r`n" + `
		"Common Name`r`n`t$($Certificate.CN)`r`n`r`n" + `
		"Subject Alternative Names`r`n`t$MultiSAN`r`n`r`n" + `
		"Algoritmo SHA`r`n`t$($Certificate.SHA)`r`n`r`n" + `
		"Password`r`n`t$($Certificate.PassWD)`r`n`r`n" + `
		"Certificate Folder`r`n`t$FolderDestination`r`n`r`n" + `
		"Certificato elaborato da`r`n`t$UserName`r`n"
		
	#----------------------------------------------------------------------------------------
	#Si compone la sezione [Extentions] per il file delle opzioni
	$Extentions= ` 
		"[Extensions]" + `
		"`n2.5.29.17=`"{text}`"" + `
		"`n_continue_=`"EMail=hostmaster@mps.it&`"" + `
		"`n_continue_=`"DNS=$($Certificate.CN)"

	#----------------------------------------------------------------------------------------
	# si aggiungono eventuali SAN. $MultiSAN potrò essere una stringa o un array
	if ($MultiSAN -ne '---') {for ($i=0; $i -lt $MultiSAN.Count; $i++) {$Extentions=$Extentions + "&`"`n_continue_=`"DNS=" + $MultiSAN[$i]}}
		
	#----------------------------------------------------------------------------------------
	#Si chiude la stringa delle estensioni con opportune "
	$Extentions= $Extentions + '"'
	$Subject= "cn=$($Certificate.CN),ou=Consorzio Operativo Gruppo MPS,o=Banca Monte dei Paschi di Siena S.p.A,c=IT,l=Siena,s=Siena"
	
	#----------------------------------------------------------------------------------------
	#Predisposizione del contenuto del file delle opzioni
	$OPT= `
		"[NewRequest]`n" + `
		"Subject=`"$Subject,PostalCode=53100`"" + `
		"`nExportable=TRUE" + `
		"`nKeyLength=2048" + `
		"`nKeySpec=1" + `
		"`nRequestType=`"PKCS10`"" + `
		"`nKeyUsage=0xA0" + `
		"`nFriendlyName=`"$($Certificate.CN)`"" + `
		"`nHashAlgorithm=$($Certificate.SHA)" + `
		"`nSMIME=False" + `
		"`nUseExistingKeySet=False" + `
		"`n[EnhancedKeyUsageExtension]" + `
		"`nOID=1.3.6.1.5.5.7.3.1" + `
		"`nOID=1.3.6.1.5.5.7.3.2`n" + `
		$Extentions
	
	if ((!$SingleStep) -or ($SingleStep -eq 'OPT')) {
		#----------------------------------------------------------------------------------------
		# Crea la directory di destinazione
		New-Item -Path $FolderDestination -ItemType directory   *>$null

		#----------------------------------------------------------------------------------------
        # Creazione del file CSV
	    $Certificate|Export-Csv $FileCSV  #*>$null

		#----------------------------------------------------------------------------------------
        # Creazione del file DTL con i primi dettagli del certificato
        Set-Content -Path $FileDTL -Value $Details -force  *>$null

        #----------------------------------------------------------------------------------------
        # Creazione del file OPT delle opzioni per il certificato
        Set-Content -Path $FileOPT -Value $OPT -force  *>$null
	}

	if ((!$SingleStep) -or ($SingleStep -eq 'CSR')) {
		#----------------------------------------------------------------------------------------
        # Creazione del file CSR Certificate Sign Request 
        & certreq -new $FileOPT $FileCSR  *>$null
		if (($Certificate.Ambito -eq 'Public-Produzione') -or ($Certificate.Ambito -eq 'Public-NPE')) {
			Write-Host -Foreground black -background $MessageColour "`tDati del certificato salvati in $FolderDestination"
			continue
		}
	}
 
	if ((!$SingleStep) -or ($SingleStep -eq 'CER')) {
		#----------------------------------------------------------------------------------------
        # Firma del certificato
        & certreq -submit -config $CertAuth -attrib $Template $FileCSR $FileCER  *>$null

		#----------------------------------------------------------------------------------------
		# Si esaminano i dati nel certificato prodotto
		$FullCertificate= $(& $OpenSSL x509 -in $FileCER -text -noout)  2>$null
		$NLinea= 0
		
		do {
			if ($FullCertificate[$NLinea] -match 'Issuer: C=.+, CN=(.+)') {$SubCA= $Matches.1}
		} while (($NLinea++ -gt $FullCertificate.Count) -or !$SubCA)
		
		$Activation= ''
		do {
			if ($FullCertificate[$NLinea] -match 'Not Before: (.{3})\s+(\d+)\s+.+:.+:.+\s(\d{4}) GMT') {
				switch ($Matches.1) {
					'Jan' {$Activation= $Matches.2 + ' Gen ' + $Matches.3}
					'Feb' {$Activation= $Matches.2 + ' Feb ' + $Matches.3}
					'Mar' {$Activation= $Matches.2 + ' Mar ' + $Matches.3}
					'Apr' {$Activation= $Matches.2 + ' Apr ' + $Matches.3}
					'May' {$Activation= $Matches.2 + ' Mag ' + $Matches.3}
					'Jun' {$Activation= $Matches.2 + ' Giu ' + $Matches.3}
					'Jul' {$Activation= $Matches.2 + ' Lug ' + $Matches.3}
					'Aug' {$Activation= $Matches.2 + ' Ago ' + $Matches.3}
					'Sep' {$Activation= $Matches.2 + ' Set ' + $Matches.3}
					'Oct' {$Activation= $Matches.2 + ' Ott ' + $Matches.3}
					'Nov' {$Activation= $Matches.2 + ' Nov ' + $Matches.3}
					'Dec' {$Activation= $Matches.2 + ' Dic ' + $Matches.3}
				}
			}
		} while (($NLinea++ -gt $FullCertificate.Count) -or !$Activation)        

		$Expiration= ''
		do {
			if ($FullCertificate[$NLinea] -match 'Not After : (.{3})\s+(\d+)\s+.+:.+:.+\s(\d{4}) GMT') {
				switch ($Matches.1) {
					'Jan' {$Expiration= $Matches.2 + ' Gen ' + $Matches.3}
					'Feb' {$Expiration= $Matches.2 + ' Feb ' + $Matches.3}
					'Mar' {$Expiration= $Matches.2 + ' Mar ' + $Matches.3}
					'Apr' {$Expiration= $Matches.2 + ' Apr ' + $Matches.3}
					'May' {$Expiration= $Matches.2 + ' Mag ' + $Matches.3}
					'Jun' {$Expiration= $Matches.2 + ' Giu ' + $Matches.3}
					'Jul' {$Expiration= $Matches.2 + ' Lug ' + $Matches.3}
					'Aug' {$Expiration= $Matches.2 + ' Ago ' + $Matches.3}
					'Sep' {$Expiration= $Matches.2 + ' Set ' + $Matches.3}
					'Oct' {$Expiration= $Matches.2 + ' Ott ' + $Matches.3}
					'Nov' {$Expiration= $Matches.2 + ' Nov ' + $Matches.3}
					'Dec' {$Expiration= $Matches.2 + ' Dic ' + $Matches.3}
				}
			}
		} while (($NLinea++ -gt $FullCertificate.Count) -or !$Expiration)        


		switch ($SubCA) {
				"AXA-Issuing-CA-PR1"										#CA Interna AXA
					{$RootCA= 'AXA-Enterprise-Root-CA'}
					
				"Sectigo RSA Extended Validation Secure Server CA"			#CA Sectigo per i certificati Extended Validation
					{$RootCA= 'USERTrust RSA Certification Authority'}
					
				"Sectigo RSA Organization Validation Secure Server CA"  	#CA Sectigo per i certificati MultiSAN
					{$RootCA= 'USERTrust RSA Certification Authority'}
					
				"USERTrust RSA Organization Validation Secure Server CA"	#CA Sectigo per i certificati RealWEB
					{$RootCA= 'USERTrust RSA Certification Authority'}
					
				"SUB01-GMPS"												#CA MPS Global per la intranet 
					{$RootCA= 'RootCA-GMPS'}
					
				"SUBMPS1-TF"												#CA MPS TestFactory
					{$RootCA= 'ROOTMPS-TF'}
					
				"SUB01-LOCAL G2"											#CA MPS Local per la intranet 
					{$RootCA= 'RootCA-GMPS'}
					
				default {Throw "`tSubCA non censita nel programma: $SubCA`r`n"}
		}
			
		$Details= `
			"Certification SUB Authority`r`n`t" + $SubCA + "`r`n`r`n" + `
			"Certification Root Authority`r`n`t" + $RootCA + "`r`n`r`n" + `
			"NotBefore`r`n`t" + $Activation + "`r`n`r`n" + `
			"NotAfter`r`n`t" + $Expiration + "`r`n`r`n"
		
		#----------------------------------------------------------------------------------------
		# Si completa il file TXT con i dettagli del certificato
		Add-Content -Path $FileDTL $Details  *>$null
		
		$Record=  '--------------------------------------------------------------------------------' + "`r`n" + `
			$Certificate.CodiceAPM + "`t" + `
			$Certificate.CN + "`t" + `
			$Certificate.SAN + "`t" + `
			$Expiration + "`t" + `
			$CertificateFolder + "`t" + `
			$SubCA + "`t" + `
			$UserName
			
		#----------------------------------------------------------------------------------------
		# Si completa il file TXT con i dettagli del certificato
		Add-Content -Path $FileDTL $Record  *>$null

    }

	if ((!$SingleStep) -or ($SingleStep -eq 'PFX')) {
	#========================================================================================
	#Rivedere la creazione dei PEM PUB e PRV con la chain 
	
		#----------------------------------------------------------------------------------------
		# Acquisizione del certificato nello storage personale
		& certreq -accept $FileCER  *>$null

		#----------------------------------------------------------------------------------------
		# Export del certificato in formato PFX con password
		& certutil -user -p $Certificate.PassWD -exportPFX my $Certificate.CN $FilePFX  *>$null

		#----------------------------------------------------------------------------------------
		# Si cancella il certificato dallo storage "my" dopo che è stato esportato
		& certutil -delstore -user my $Certificate.CN  *>$null

		#----------------------------------------------------------------------------------------
		# Estrazione dal PFX della chiave privata del certificato in formato X509 PEM
		& $OpenSSL pkcs12 -in $FilePFX -out $FTmpPRV -clcerts -nodes -password pass:$($Certificate.PassWD)  *>$null

		#----------------------------------------------------------------------------------------
		# Si esaminano i dati nel certificato prodotto se la $SubCA non è già stata inizializzata 
		# nell'elaborazione del CER
		if (!$SubCA) {
			$FullCertificate= $(& $OpenSSL x509 -in $FileCER -text -noout)  2>$null

			$NLinea= 0			
			do {
				if ($FullCertificate[$NLinea] -match 'Issuer: C=.+, CN=(.+)') {$SubCA= $Matches.1}
			} while (($NLinea++ -gt $FullCertificate.Count) -or !$SubCA)

			switch ($SubCA) {
				"AXA-Issuing-CA-PR1"										#CA Interna AXA
					{$RootCA= 'AXA-Enterprise-Root-CA'}
					
				"Sectigo RSA Extended Validation Secure Server CA"			#CA Sectigo per i certificati Extended Validation
					{$RootCA= 'USERTrust RSA Certification Authority'}
					
				"Sectigo RSA Organization Validation Secure Server CA"  	#CA Sectigo per i certificati MultiSAN
					{$RootCA= 'USERTrust RSA Certification Authority'}
					
				"USERTrust RSA Organization Validation Secure Server CA"	#CA Sectigo per i certificati RealWEB
					{$RootCA= 'USERTrust RSA Certification Authority'}
					
				"SUB01-GMPS"												#CA MPS Global per la intranet 
					{$RootCA= 'RootCA-GMPS'}
					
				"SUBMPS1-TF"												#CA MPS TestFactory
					{$RootCA= 'ROOTMPS-TF'}
					
				"SUB01-LOCAL G2"											#CA MPS Local per la intranet 
					{$RootCA= 'RootCA-GMPS'}
					
				default {Throw "`tSubCA non censita nel programma: $SubCA`r`n"}
			}
		}

		$FileSubCA= $NAS + $SubCA + '\' + $SubCA + '.CRT'
		$FileRootCA= $NAS + $RootCA + '\' + $RootCA + '.CRT'
		
		if (!(Test-Path $FileSubCA)) {Throw "Certificato della SubCA $FileSubCA non trovato: $FileSubCA"}
		if (!(Test-Path $FileRootCA)) {Throw "Certificato della RootCA $FileRootCA non trovato: $FileRootCA"}

		#----------------------------------------------------------------------------------------
		#Si compone la parte PRIVATA del certificato con la catena di certificazione
		$CertPRV= Get-Content -Path $FTmpPRV
		$CertPUB= $CertPUB + "`r`n`r`n"
		#$CertPRV= $CertPRV + "Certificato di SubCA:`r`n`t$SubCA"
		$CertPRV= $CertPRV + $(Get-Content -Path $FileSubCA)
		$CertPUB= $CertPUB + "`r`n`r`n"
		#$CertPRV= $CertPRV + "Certificato di RootCA:`r`n`t$RootCA"
		$CertPRV= $CertPRV + $(Get-Content -Path $FileRootCA)
		$CertPRV | Set-Content -Path $FilePRV -force  *>$null
	}

	#----------------------------------------------------------------------------------------
	# Si Cancellano i file non necessari
    if (Test-Path $FileRSP) {Remove-Item -Path $FileRSP}
    if (Test-Path $FTmpPUB) {Remove-Item -Path $FTmpPUB}
    if (Test-Path $FTmpPRV) {Remove-Item -Path $FTmpPRV}

    Write-Host -Foreground black -background $MessageColour "`tDati del certificato salvati in $FolderDestination"

}
Write-Host	
exit


    
 <#           
        #--------------------------------------------------

        #--------------------------------------------------
        #Per la CA pubblica si salvano i file e si passa al certificato successivo
        if (($Certificate.Ambito -eq 'Public-Produzione') -or ($Certificate.Ambito -eq 'Public-NPE')) {
            Write-Host -Foreground Black -Background Green "`tIl file CSR per la richiesta del certificato è stato salvato in:"
            Write-Host "`t$FolderDestination"
            continue
        }
    }

	
        
    
    #--------------------------------------------------
    # Estrazione dal PFX della chiave pubblica del certificato in formato X509 PEM
    & $OpenSSL pkcs12 -in $FilePFX -out $FTmpPUB -clcerts -nodes -nokeys -password pass:$($Certificate.PassWD)  *>$null
        
        
    #--------------------------------------------------
    #Si compone la parte PUBBLICA del certificato con la catena di certificazione
    $CertPUB= Get-Content -Path $FTmpPUB
    $CertPUB= $CertPUB + "`r`n`r`n"
    $CertPUB= $CertPUB + $(Get-Content -Path $FileSubCA)
    $CertPUB= $CertPUB + "`r`n`r`n"
    #$CertPUB= $CertPUB + "Certificato di RootCA:`r`n`t$RootCA"
    $CertPUB= $CertPUB + $(Get-Content -Path $FileRootCA)
    $CertPUB | Set-Content -Path $FilePUB -force  *>$null
    
    
    #--------------------------------------------------
    #Si crea il Java Key Store con il certificato Alias= $DNSName
	if ($(keytool -list -storetype pkcs12 -keystore $FilePFX -deststorepass $Certificate.PassWD)[6] -match "(.*?),.*") {
		$CertificateAlias= $Matches[1]
	}
	else {Throw "Non trovato il certificato nel PFX"}
	keytool -importkeystore `
        -srcstoretype pkcs12 -srckeystore $FilePFX -srcstorepass $Certificate.PassWD -srcalias $CertificateAlias `
        -deststoretype jks -destkeystore $FileJKS -deststorepass $Certificate.PassWD -destalias $Certificate.CN `
        -noprompt 
	keytool -import -alias $SubCA -file $FileSubCA -keystore $FileJKS -deststorepass $Certificate.PassWD -noprompt  *>$null
	keytool -import -alias $RootCA -file $FileRootCA -trustcacerts -keystore $FileJKS -deststorepass $Certificate.PassWD -noprompt  *>$null

    #--------------------------------------------------
    # Se il certificato è al primo rilascio ne viene fatta una copia anche nella directory padre di R1
    if ($Release -eq 1) {
        if (Test-Path $FilePUB) {Copy-Item -Path $FilePUB -Destination "$CertificateFolder"}
    }


    Write-Host -Foreground black -background Green "`tDati del certificato salvati in:"
	Write-Host "`t$FolderDestination"
}

Write-Host

#>
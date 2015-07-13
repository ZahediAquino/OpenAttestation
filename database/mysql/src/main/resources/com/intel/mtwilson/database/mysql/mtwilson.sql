CREATE TABLE `mw_changelog` (
  `ID` decimal(20,0) NOT NULL,
  `APPLIED_AT` varchar(25) NOT NULL,
  `DESCRIPTION` varchar(255) NOT NULL,
  PRIMARY KEY (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

CREATE TABLE `mw_oem` (
  `ID` int(11) NOT NULL AUTO_INCREMENT,
  `NAME` varchar(100) DEFAULT NULL,
  `DESCRIPTION` varchar(200) DEFAULT NULL,
  PRIMARY KEY (`ID`),
  UNIQUE KEY `tbl_oem.UNIQUE` (`NAME`)
) ENGINE=InnoDB AUTO_INCREMENT=12 DEFAULT CHARSET=latin1;
CREATE TABLE `mw_os` (
  `ID` int(11) NOT NULL AUTO_INCREMENT,
  `NAME` varchar(100) NOT NULL,
  `VERSION` varchar(50) NOT NULL,
  `DESCRIPTION` varchar(200) DEFAULT NULL,
  PRIMARY KEY (`ID`),
  UNIQUE KEY `tbl_os_name_version.UNIQUE` (`NAME`,`VERSION`)
) ENGINE=InnoDB AUTO_INCREMENT=15 DEFAULT CHARSET=latin1;
CREATE TABLE `mw_mle` (
  `ID` int(11) NOT NULL AUTO_INCREMENT,
  `Name` varchar(100) NOT NULL,
  `Version` varchar(100) NOT NULL,
  `Attestation_Type` varchar(20) NOT NULL DEFAULT 'PCR',
  `MLE_Type` varchar(20) NOT NULL DEFAULT 'VMM',
  `Required_Manifest_List` varchar(100) NOT NULL,
  `Description` varchar(100) DEFAULT NULL,
  `OS_ID` int(11) DEFAULT NULL,
  `OEM_ID` int(11) DEFAULT NULL,
  PRIMARY KEY (`ID`),
  UNIQUE KEY `MLE_ID` (`ID`),
  KEY `MLE_OEM_FK` (`OEM_ID`),
  KEY `MLE_OS_FK` (`OS_ID`),
  CONSTRAINT `MLE_OEM_FK` FOREIGN KEY (`OEM_ID`) REFERENCES `mw_oem` (`ID`),
  CONSTRAINT `MLE_OS_FK` FOREIGN KEY (`OS_ID`) REFERENCES `mw_os` (`ID`)
) ENGINE=InnoDB AUTO_INCREMENT=33 DEFAULT CHARSET=latin1;
CREATE TABLE `mw_hosts` (
  `ID` int(11) NOT NULL AUTO_INCREMENT,
  `BIOS_MLE_ID` int(11) NOT NULL,
  `VMM_MLE_ID` int(11) NOT NULL,
  `Name` varchar(40) NOT NULL,
  `IPAddress` varchar(20) DEFAULT NULL,
  `Port` int(11) NOT NULL,
  `Description` varchar(100) DEFAULT NULL,
  `AddOn_Connection_Info` text,
  `AIK_Certificate` text,
  `AIK_SHA1` varchar(40) DEFAULT NULL,
  `Email` varchar(45) DEFAULT NULL,
  `Error_Code` int(11) DEFAULT NULL,
  `Error_Description` varchar(100) DEFAULT NULL,
  `Location` varchar(200) DEFAULT NULL,
  `TlsPolicy` varchar(255) NOT NULL DEFAULT 'TRUST_FIRST_CERTIFICATE',
  `TlsKeystore` blob,
  PRIMARY KEY (`ID`),
  KEY `BIOS_MLE_ID` (`BIOS_MLE_ID`),
  KEY `VMM_MLE_ID` (`VMM_MLE_ID`),
  CONSTRAINT `BIOS_MLE_ID` FOREIGN KEY (`BIOS_MLE_ID`) REFERENCES `mw_mle` (`ID`) ON DELETE NO ACTION ON UPDATE NO ACTION,
  CONSTRAINT `VMM_MLE_ID` FOREIGN KEY (`VMM_MLE_ID`) REFERENCES `mw_mle` (`ID`) ON DELETE NO ACTION ON UPDATE NO ACTION
) ENGINE=InnoDB AUTO_INCREMENT=69 DEFAULT CHARSET=latin1;

CREATE TABLE `mw_keystore` (
  `ID` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  `keystore` blob NOT NULL,
  `provider` varchar(255) NOT NULL,
  `comment` text,
  PRIMARY KEY (`ID`),
  UNIQUE KEY `name_index` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
CREATE TABLE `mw_mle_source` (
  `ID` int(11) NOT NULL AUTO_INCREMENT,
  `MLE_ID` int(11) NOT NULL,
  `Host_Name` varchar(100) DEFAULT NULL,
  PRIMARY KEY (`ID`),
  KEY `MLE_ID` (`MLE_ID`),
  CONSTRAINT `MLE_ID` FOREIGN KEY (`MLE_ID`) REFERENCES `mw_mle` (`ID`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
CREATE TABLE `mw_pcr_manifest` (
  `ID` int(11) NOT NULL AUTO_INCREMENT,
  `MLE_ID` int(11) NOT NULL,
  `Name` varchar(20) NOT NULL,
  `Value` varchar(100) NOT NULL,
  `PCR_Description` varchar(100) DEFAULT NULL,
  PRIMARY KEY (`ID`),
  KEY `PCR_MLE_ID` (`MLE_ID`),
  CONSTRAINT `PCR_MLE_ID` FOREIGN KEY (`MLE_ID`) REFERENCES `mw_mle` (`ID`) ON DELETE NO ACTION ON UPDATE NO ACTION
) ENGINE=InnoDB AUTO_INCREMENT=40 DEFAULT CHARSET=latin1;
CREATE TABLE `mw_request_queue` (
  `ID` int(11) NOT NULL AUTO_INCREMENT,
  `Host_ID` int(11) NOT NULL,
  `Is_Processed` tinyint(1) NOT NULL,
  `Trust_Status` varchar(15) DEFAULT NULL,
  `RQ_Error_Code` int(11) DEFAULT NULL,
  `RQ_Error_Description` varchar(100) DEFAULT NULL,
  PRIMARY KEY (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
CREATE TABLE `mw_ta_log` (
  `ID` int(11) NOT NULL AUTO_INCREMENT,
  `Host_ID` int(11) NOT NULL,
  `MLE_ID` int(11) NOT NULL,
  `Manifest_Name` varchar(25) NOT NULL,
  `Manifest_Value` varchar(100) NOT NULL,
  `Trust_Status` tinyint(1) NOT NULL,
  `Error` varchar(100) DEFAULT NULL,
  `Updated_On` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`ID`)
) ENGINE=InnoDB AUTO_INCREMENT=10349 DEFAULT CHARSET=latin1;

INSERT INTO `mw_oem` (`ID`, `NAME`, `DESCRIPTION`) VALUES (5,'GENERIC','Default Oem for testing');
INSERT INTO `mw_oem` (`ID`, `NAME`, `DESCRIPTION`) VALUES (8,'EPSD','Intel white boxes');
INSERT INTO `mw_oem` (`ID`, `NAME`, `DESCRIPTION`) VALUES (9,'HP','HP Systems');
INSERT INTO `mw_os` (`ID`, `NAME`, `VERSION`, `DESCRIPTION`) VALUES (7,'RHEL','6.1',NULL);
INSERT INTO `mw_os` (`ID`, `NAME`, `VERSION`, `DESCRIPTION`) VALUES (8,'RHEL','6.2',NULL);
INSERT INTO `mw_os` (`ID`, `NAME`, `VERSION`, `DESCRIPTION`) VALUES (9,'UBUNTU','11.10',NULL);
INSERT INTO `mw_os` (`ID`, `NAME`, `VERSION`, `DESCRIPTION`) VALUES (10,'SUSE','11 P2',NULL);

-- the following changelog statements cover the above schema; by inserting them into the database we facilitate a future upgrade to mt wilson premium because the installer will be able to use these changelog statements to determine what other sql scripts should run during the upgrade

INSERT INTO `mw_changelog` (`ID`, `APPLIED_AT`, `DESCRIPTION`) VALUES (20120101000000,NOW(),'core - bootstrap');
INSERT INTO `mw_changelog` (`ID`, `APPLIED_AT`, `DESCRIPTION`) VALUES (20120327214603,NOW(),'core - create changelog');
INSERT INTO `mw_changelog` (`ID`, `APPLIED_AT`, `DESCRIPTION`) VALUES (20120328172740,NOW(),'core - create 0.5.1 schema');
INSERT INTO `mw_changelog` (`ID`, `APPLIED_AT`, `DESCRIPTION`) VALUES (20120328173612,NOW(),'core - create 0.5.1 data');
INSERT INTO `mw_changelog` (`ID`, `APPLIED_AT`, `DESCRIPTION`) VALUES (20120831000000,NOW(),'core - patch rc2');
INSERT INTO `mw_changelog` (`ID`, `APPLIED_AT`, `DESCRIPTION`) VALUES (20120920085200,NOW(),'core - patch for 1.1');
INSERT INTO `mw_changelog` (`ID`, `APPLIED_AT`, `DESCRIPTION`) VALUES (20120920085201,NOW(),'core - patch for 1.1 rename tables');
INSERT INTO `mw_changelog` (`ID`, `APPLIED_AT`, `DESCRIPTION`) VALUES (20121226120200,NOW(),'core - patch for RC3 to remove created_by, updated_by, created_on & updated_on fields');
INSERT INTO `mw_changelog` (`ID`, `APPLIED_AT`, `DESCRIPTION`) VALUES (20130106235900,NOW(),'core - patch for 1.1 adding tls policy enforcement');
INSERT INTO `mw_changelog` (`ID`, `APPLIED_AT`, `DESCRIPTION`) VALUES (20130407075500,NOW(),'core - Mt Wilson 1.2 adds AIK_SHA1 field to mw_hosts');



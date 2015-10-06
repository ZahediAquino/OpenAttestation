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






-- ASSET TAGGING DB Changes
CREATE TABLE `mw_asset_tag_certificate` (
  `ID` INT(11) NOT NULL AUTO_INCREMENT,
  `Host_ID` INT(11) DEFAULT NULL,
  `UUID` VARCHAR(255) DEFAULT NULL,
  `Certificate` BLOB NOT NULL,
  `SHA1_Hash` BINARY(20) DEFAULT NULL,
  `PCREvent` BINARY(20) DEFAULT NULL,
  `Revoked` BOOLEAN DEFAULT NULL,
  `NotBefore` DATETIME DEFAULT NULL,
  `NotAfter` DATETIME DEFAULT NULL,
  PRIMARY KEY (`ID`),
  KEY `Host_ID` (`Host_ID`),
  CONSTRAINT `Host_ID` FOREIGN KEY (`Host_ID`) REFERENCES `mw_hosts` (`ID`) ON DELETE NO ACTION ON UPDATE NO ACTION); 

INSERT INTO `mw_changelog` (`ID`, `APPLIED_AT`, `DESCRIPTION`) VALUES (20130814154300,NOW(),'Patch for creating the Asset Tag certificate table.');


ALTER TABLE `mw_asset_tag_certificate` ADD COLUMN `uuid_hex` CHAR(36) NULL;
UPDATE mw_asset_tag_certificate SET uuid_hex = (SELECT uuid());
ALTER TABLE `mw_asset_tag_certificate` ADD COLUMN `create_time` BIGINT  DEFAULT NULL AFTER `uuid_hex` ;


CREATE  TABLE `mw_host_tpm_password` (
  `id` CHAR(36) NOT NULL ,
  `password` TEXT NOT NULL ,
  `modifiedOn` DATETIME NOT NULL ,
  PRIMARY KEY (`id`) );
  
CREATE  TABLE `mw_tag_kvattribute` (
  `id` CHAR(36) NOT NULL ,
  `name` VARCHAR(255) NOT NULL ,
  `value` VARCHAR(255) NOT NULL ,
  PRIMARY KEY (`id`), 
  UNIQUE KEY (`name`, `value`));
 
CREATE  TABLE `mw_tag_selection` (
  `id` CHAR(36) NOT NULL ,
  `name` VARCHAR(255) NOT NULL ,
  `description` TEXT NULL,
  PRIMARY KEY (`id`) );
  
CREATE  TABLE `mw_tag_selection_kvattribute` (
  `id` CHAR(36) NOT NULL ,
  `selectionId` CHAR(36) NOT NULL ,
  `kvAttributeId` CHAR(36) NOT NULL ,
  PRIMARY KEY (`id`) );
  
CREATE  TABLE `mw_tag_certificate` (
  `id` CHAR(36) NOT NULL ,
  `certificate` BLOB NOT NULL ,
  `sha1` CHAR(40) NOT NULL ,
  `sha256` CHAR(64) NOT NULL ,
  `subject` VARCHAR(255) NOT NULL ,
  `issuer` VARCHAR(255) NOT NULL ,
  `notBefore` DATETIME NOT NULL ,
  `notAfter` DATETIME NOT NULL ,
  `revoked` BOOLEAN NOT NULL DEFAULT FALSE ,
  PRIMARY KEY (`id`) );
  
  CREATE  TABLE `mw_tag_certificate_request` (
  `id` CHAR(36) NOT NULL ,
  `subject` VARCHAR(255) NOT NULL ,
  `status` VARCHAR(255) NULL , 
  `content` BLOB NOT NULL,
  `contentType` VARCHAR(255) NOT NULL,
  PRIMARY KEY (`id`) );
  
  
  CREATE  TABLE `mw_configuration` (
  `id` CHAR(36) NOT NULL ,
  `name` VARCHAR(255) NOT NULL ,
  `content` TEXT NULL ,
  PRIMARY KEY (`id`) );

ALTER TABLE `mw_hosts` ADD `hardware_uuid` VARCHAR(254);


ALTER TABLE `mw_oem` ADD COLUMN `uuid_hex` CHAR(36) NULL;
UPDATE mw_oem SET uuid_hex = (SELECT uuid());



ALTER TABLE `mw_os` ADD COLUMN `uuid_hex` CHAR(36) NULL;
UPDATE mw_os SET uuid_hex = (SELECT uuid());



ALTER TABLE `mw_mle` ADD COLUMN `uuid_hex` CHAR(36) NULL;
UPDATE mw_mle SET uuid_hex = (SELECT uuid());

ALTER TABLE `mw_mle` ADD COLUMN `oem_uuid_hex` CHAR(36) NULL;
UPDATE mw_mle mm SET oem_uuid_hex = (SELECT moem.uuid_hex FROM mw_oem moem WHERE moem.ID = mm.OEM_ID);
-- Adds the reference to the OS UUID column in the MLE table
ALTER TABLE `mw_mle` ADD COLUMN `os_uuid_hex` CHAR(36) NULL;
UPDATE mw_mle mm SET os_uuid_hex = (SELECT mos.uuid_hex FROM mw_os mos WHERE mos.ID = mm.OS_ID);


-- Updates for the MLE Source table
ALTER TABLE `mw_mle_source` ADD COLUMN `uuid_hex` CHAR(36) NULL;
UPDATE mw_mle_source SET uuid_hex = (SELECT uuid());
-- Adds the reference to the MLE UUID column in the MW_MLE_Source table
ALTER TABLE `mw_mle_source` ADD COLUMN `mle_uuid_hex` CHAR(36) NULL;
UPDATE mw_mle_source ms SET mle_uuid_hex = (SELECT m.uuid_hex FROM mw_mle m WHERE m.ID = ms.MLE_ID);


-- Updates for the PCR Manifest table
ALTER TABLE `mw_pcr_manifest` ADD COLUMN `uuid_hex` CHAR(36) NULL;
UPDATE mw_pcr_manifest SET uuid_hex = (SELECT uuid());
-- Adds the reference to the MLE UUID column in the MW_PCR_Manifest table
ALTER TABLE `mw_pcr_manifest` ADD COLUMN `mle_uuid_hex` CHAR(36) NULL;
UPDATE mw_pcr_manifest mpm SET mle_uuid_hex = (SELECT m.uuid_hex FROM mw_mle m WHERE m.ID = mpm.MLE_ID);



-- Updates for the Host table
ALTER TABLE `mw_hosts` ADD COLUMN `uuid_hex` CHAR(36) NULL;
UPDATE mw_hosts SET uuid_hex = (SELECT uuid());
-- Adds the reference to the BIOS MLE UUID column in the Hosts table
ALTER TABLE `mw_hosts` ADD COLUMN `bios_mle_uuid_hex` CHAR(36) NULL;
UPDATE mw_hosts mh SET bios_mle_uuid_hex = (SELECT mm.uuid_hex FROM mw_mle mm WHERE mm.ID = mh.BIOS_MLE_ID);
-- Adds the reference to the VMM MLE UUID column in the Hosts table
ALTER TABLE `mw_hosts` ADD COLUMN `vmm_mle_uuid_hex` CHAR(36) NULL;
UPDATE mw_hosts mh SET vmm_mle_uuid_hex = (SELECT mm.uuid_hex FROM mw_mle mm WHERE mm.ID = mh.VMM_MLE_ID);


-- Updates for the MW_TA_Log table
ALTER TABLE `mw_ta_log` ADD COLUMN `uuid_hex` CHAR(36) NULL;
UPDATE mw_ta_log SET uuid_hex = (SELECT uuid());
-- Adds the reference to the HOST UUID column in the Hosts table
ALTER TABLE `mw_ta_log` ADD COLUMN `host_uuid_hex` CHAR(36) NULL;
UPDATE mw_ta_log mtl SET host_uuid_hex = (SELECT mh.uuid_hex FROM mw_hosts mh WHERE mh.ID = mtl.Host_ID);


-- This script creates the file table

CREATE  TABLE `mw_file` (
  `id` CHAR(36) NOT NULL ,
  `name` VARCHAR(255) NULL ,
  `contentType` VARCHAR(255) NULL ,
  `content` BLOB NULL ,
  PRIMARY KEY (`id`) );


-- mw_package_namespace

CREATE TABLE `mw_package_namespace` (
  `ID` int(11) NOT NULL AUTO_INCREMENT,
  `Name` varchar(45) NOT NULL,
  `VendorName` varchar(45) NOT NULL,
  PRIMARY KEY (`ID`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=latin1;

-- mw_event_type table

CREATE TABLE `mw_event_type` (
  `ID` int(11) NOT NULL AUTO_INCREMENT,
  `Name` varchar(75) NOT NULL,
  `FieldName` varchar(45) NOT NULL,
  PRIMARY KEY (`ID`)
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=latin1;

-- mw_module_manifest table

CREATE TABLE `mw_module_manifest` (
  `ID` int(11) NOT NULL AUTO_INCREMENT,
  `MLE_ID` int(11) NOT NULL,
  `Event_ID` int(11) NOT NULL,
  `NameSpace_ID` int(11) NOT NULL,
  `ComponentName` varchar(150) NOT NULL,
  `DigestValue` varchar(100) DEFAULT NULL,
  `ExtendedToPCR` varchar(5) DEFAULT NULL,
  `PackageName` varchar(45) DEFAULT NULL,
  `PackageVendor` varchar(45) DEFAULT NULL,
  `PackageVersion` varchar(45) DEFAULT NULL,
  `UseHostSpecificDigestValue` tinyint(1) DEFAULT NULL,
  `Description` varchar(100) DEFAULT NULL,

  PRIMARY KEY (`ID`),
  KEY `Module_MLE_ID` (`MLE_ID`),

  KEY `Module_NameSpace_ID` (`NameSpace_ID`),
  KEY `Module_Event_ID` (`Event_ID`),
  CONSTRAINT `Module_MLE_ID` FOREIGN KEY (`MLE_ID`) REFERENCES `mw_mle` (`ID`) ON DELETE NO ACTION ON UPDATE NO ACTION,
  CONSTRAINT `Module_NameSpace_ID` FOREIGN KEY (`NameSpace_ID`) REFERENCES `mw_package_namespace` (`ID`) ON DELETE NO ACTION ON UPDATE NO ACTION,
  CONSTRAINT `Module_Event_ID` FOREIGN KEY (`Event_ID`) REFERENCES `mw_event_type` (`ID`) ON DELETE NO ACTION ON UPDATE NO ACTION
) ENGINE=InnoDB AUTO_INCREMENT=71 DEFAULT CHARSET=latin1;

-- Creates the host specific manifest table

CREATE TABLE `mw_host_specific_manifest` (
  `ID` int(11) NOT NULL AUTO_INCREMENT,
  `Module_Manifest_ID` int(11) NOT NULL,
  `Host_ID` int(11) NOT NULL,
  `DigestValue` varchar(100) NOT NULL,
  PRIMARY KEY (`ID`),
  KEY `Module_Manifest_ID` (`Module_Manifest_ID`),
  CONSTRAINT `Module_Manifest_ID` FOREIGN KEY (`Module_Manifest_ID`) REFERENCES `mw_module_manifest` (`ID`) ON DELETE NO ACTION ON UPDATE NO ACTION
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=latin1;

-- Module manifest log supports the failure report feature
CREATE TABLE `mw_module_manifest_log` (
  `ID` int(11) NOT NULL AUTO_INCREMENT,
  `ta_log_id` int(11) NOT NULL,
  `name` varchar(100) DEFAULT NULL,
  `value` varchar(100) DEFAULT NULL,
  `whitelist_value` varchar(100) DEFAULT NULL,
  PRIMARY KEY (`ID`),
  KEY `TA_LOG_FK` (`ta_log_id`),
  CONSTRAINT `TA_LOG_FK` FOREIGN KEY (`ta_log_id`) REFERENCES `mw_ta_log` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;


CREATE TABLE `mw_location_pcr` (
  `ID` int(11) NOT NULL AUTO_INCREMENT,
  `location` varchar(200) NOT NULL,
  `pcr_value` varchar(100) NOT NULL,
  PRIMARY KEY (`ID`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=latin1 COMMENT='Mapping between the pcr values and location';


ALTER TABLE `mw_module_manifest` ADD COLUMN `uuid_hex` CHAR(36) NULL;
UPDATE mw_module_manifest SET uuid_hex = (SELECT uuid());

ALTER TABLE `mw_module_manifest` ADD COLUMN `mle_uuid_hex` CHAR(36) NULL;
UPDATE mw_module_manifest mpm SET mle_uuid_hex = (SELECT m.uuid_hex FROM mw_mle m WHERE m.ID = mpm.MLE_ID);

ALTER TABLE `mw_ta_log` ADD COLUMN `mle_uuid_hex` CHAR(36) NULL;
UPDATE mw_ta_log mpm SET mle_uuid_hex = (SELECT m.uuid_hex FROM mw_mle m WHERE m.ID = mpm.MLE_ID);


CREATE TABLE `mw_saml_assertion` (
  `ID` int(11) NOT NULL AUTO_INCREMENT,
  `host_id` int(11) NOT NULL,
  `saml` text,
  `expiry_ts` datetime NOT NULL,
  `bios_trust` tinyint(1) NOT NULL,
  `vmm_trust` tinyint(1) NOT NULL,
  `error_code` varchar(50) DEFAULT NULL,
  `error_message` varchar(200) DEFAULT NULL,
  `created_ts` datetime DEFAULT NULL,
  PRIMARY KEY (`ID`),
  KEY `tbl_hosts_fk` (`host_id`),
  CONSTRAINT `tbl_hosts_fk` FOREIGN KEY (`host_id`) REFERENCES `mw_hosts` (`ID`)
) ENGINE=InnoDB AUTO_INCREMENT=11 DEFAULT CHARSET=latin1 COMMENT='SAML assertion cache';

ALTER TABLE mw_saml_assertion ADD COLUMN uuid_hex CHAR(36) NULL;
ALTER TABLE mw_saml_assertion ADD COLUMN trust_report TEXT DEFAULT NULL;

INSERT INTO `mw_event_type` (`ID`, `Name`, `FieldName`) VALUES (1,'Vim25Api.HostTpmSoftwareComponentEventDetails','componentName');
INSERT INTO `mw_event_type` (`ID`, `Name`, `FieldName`) VALUES (2,'Vim25Api.HostTpmOptionEventDetails','bootOptions');
INSERT INTO `mw_event_type` (`ID`, `Name`, `FieldName`) VALUES (3,'Vim25Api.HostTpmBootSecurityOptionEventDetails','bootSecurityOption');
INSERT INTO `mw_event_type` (`ID`, `Name`, `FieldName`) VALUES (4,'Vim25Api.HostTpmCommandEventDetails','commandLine');
INSERT INTO `mw_event_type` (`ID`, `Name`, `FieldName`) VALUES (5,'OpenSource.EventName','OpenSource');
INSERT INTO `mw_package_namespace` (`ID`, `Name`, `VendorName`) VALUES (1,'Standard_Global_NS','VMware');

INSERT INTO mw_changelog (ID, APPLIED_AT, DESCRIPTION) VALUES (20130430154900,NOW(),'patch for adding a new entry into the event type table for open source module attestation.');

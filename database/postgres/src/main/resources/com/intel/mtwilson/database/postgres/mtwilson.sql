CREATE TABLE mw_changelog (
  ID decimal(20,0) NOT NULL,
  APPLIED_AT timestamp NOT NULL,
  DESCRIPTION varchar(255) NOT NULL,
  PRIMARY KEY (ID)
);

CREATE SEQUENCE mw_oem_serial;
CREATE TABLE mw_oem (
  ID integer NOT NULL DEFAULT nextval('mw_oem_serial'),
  NAME varchar(100) UNIQUE DEFAULT NULL,
  DESCRIPTION varchar(200) DEFAULT NULL,
  PRIMARY KEY (ID)
);

CREATE SEQUENCE mw_os_serial;
CREATE TABLE mw_os (
  ID integer NOT NULL DEFAULT nextval('mw_os_serial'),
  NAME varchar(100) NOT NULL,
  VERSION varchar(50) NOT NULL,
  DESCRIPTION varchar(200) DEFAULT NULL,
  PRIMARY KEY (ID),
  CONSTRAINT mw_os_name_version UNIQUE(NAME,VERSION)
);

CREATE SEQUENCE mw_mle_serial;
CREATE TABLE mw_mle (
  ID integer NOT NULL DEFAULT nextval('mw_mle_serial'),
  Name varchar(100) NOT NULL,
  Version varchar(100) NOT NULL,
  Attestation_Type varchar(20) NOT NULL DEFAULT 'PCR',
  MLE_Type varchar(20) NOT NULL DEFAULT 'VMM',
  Required_Manifest_List varchar(100) NOT NULL,
  Description varchar(100) DEFAULT NULL,
  OS_ID integer DEFAULT NULL,
  OEM_ID integer DEFAULT NULL,
  PRIMARY KEY (ID)
);

CREATE SEQUENCE mw_hosts_serial;
CREATE TABLE mw_hosts (
  ID integer NOT NULL DEFAULT nextval('mw_hosts_serial'),
  BIOS_MLE_ID integer NOT NULL,
  VMM_MLE_ID integer NOT NULL,
  Name varchar(40) NOT NULL,
  IPAddress varchar(20) DEFAULT NULL,
  Port integer NOT NULL,
  Description varchar(100) DEFAULT NULL,
  AddOn_Connection_Info text,
  AIK_Certificate text,
  AIK_SHA1 varchar(40) DEFAULT NULL,
  Email varchar(45) DEFAULT NULL,
  Error_Code integer DEFAULT NULL,
  Error_Description varchar(100) DEFAULT NULL,
  Location varchar(200) DEFAULT NULL,
  TlsPolicy varchar(255) NOT NULL DEFAULT 'TRUST_FIRST_CERTIFICATE',
  TlsKeystore bytea NULL,
  PRIMARY KEY (ID),
  CONSTRAINT BIOS_MLE_ID FOREIGN KEY (BIOS_MLE_ID) REFERENCES mw_mle (ID) ON DELETE NO ACTION ON UPDATE NO ACTION,
  CONSTRAINT VMM_MLE_ID FOREIGN KEY (VMM_MLE_ID) REFERENCES mw_mle (ID) ON DELETE NO ACTION ON UPDATE NO ACTION
);

CREATE SEQUENCE mw_keystore_serial;
CREATE TABLE mw_keystore (
  ID integer NOT NULL DEFAULT nextval('mw_keystore_serial'),
  name varchar(255) NOT NULL,
  keystore bytea NOT NULL,
  provider varchar(255) NOT NULL,
  comment text,
  PRIMARY KEY (ID),
  CONSTRAINT name_index UNIQUE(name)
);

CREATE SEQUENCE mw_mle_source_serial;
CREATE  TABLE mw_mle_source (
  ID integer NOT NULL DEFAULT nextval('mw_mle_source_serial'),
  MLE_ID integer NOT NULL ,
  Host_Name VARCHAR(100) NULL ,
  PRIMARY KEY (ID) ,
  --INDEX MLE_ID (MLE_ID ASC) ,
  CONSTRAINT MLE_ID
    FOREIGN KEY (MLE_ID )
    REFERENCES mw_mle (ID )
    ON DELETE CASCADE
    ON UPDATE CASCADE
);

CREATE SEQUENCE mw_pcr_manifest_serial;
CREATE TABLE mw_pcr_manifest (
  ID integer NOT NULL DEFAULT nextval('mw_pcr_manifest_serial'),
  MLE_ID integer NOT NULL,
  Name varchar(20) NOT NULL,
  Value varchar(100) NOT NULL,
  PCR_Description varchar(100) DEFAULT NULL,
  PRIMARY KEY (ID),
  CONSTRAINT PCR_Created_By FOREIGN KEY (Created_By) REFERENCES mw_db_portal_user (ID) ON DELETE NO ACTION ON UPDATE NO ACTION,
  CONSTRAINT PCR_Last_Updated_By FOREIGN KEY (Updated_By) REFERENCES mw_db_portal_user (ID) ON DELETE NO ACTION ON UPDATE NO ACTION,
  CONSTRAINT PCR_MLE_ID FOREIGN KEY (MLE_ID) REFERENCES mw_mle (ID) ON DELETE NO ACTION ON UPDATE NO ACTION
);


CREATE SEQUENCE mw_request_queue_serial;
CREATE TABLE mw_request_queue (
  ID integer NOT NULL DEFAULT nextval('mw_request_queue_serial'),
  Host_ID integer NOT NULL,
  Is_Processed boolean NOT NULL DEFAULT '0',
  Trust_Status varchar(15) DEFAULT NULL,
  RQ_Error_Code integer DEFAULT NULL,
  RQ_Error_Description varchar(100) DEFAULT NULL,
  PRIMARY KEY (ID)
);

CREATE SEQUENCE mw_ta_log_serial;
CREATE TABLE mw_ta_log (
  ID integer NOT NULL DEFAULT nextval('mw_ta_log_serial'),
  Host_ID integer NOT NULL,
  MLE_ID integer NOT NULL,
  Manifest_Name varchar(25) NOT NULL,
  Manifest_Value varchar(100) NOT NULL,
  Trust_Status boolean NOT NULL,
  Error varchar(100) DEFAULT NULL,
  Updated_On timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (ID)
);

INSERT INTO mw_oem (ID, NAME, DESCRIPTION) VALUES (5,'GENERIC','Default Oem for testing');
INSERT INTO mw_oem (ID, NAME, DESCRIPTION) VALUES (8,'EPSD','Intel white boxes');
INSERT INTO mw_oem (ID, NAME, DESCRIPTION) VALUES (9,'HP','HP Systems');
INSERT INTO mw_os (ID, NAME, VERSION, DESCRIPTION) VALUES (7,'RHEL','6.1',NULL);
INSERT INTO mw_os (ID, NAME, VERSION, DESCRIPTION) VALUES (8,'RHEL','6.2',NULL);
INSERT INTO mw_os (ID, NAME, VERSION, DESCRIPTION) VALUES (9,'UBUNTU','11.10',NULL);
INSERT INTO mw_os (ID, NAME, VERSION, DESCRIPTION) VALUES (10,'SUSE','11 P2',NULL);

-- the following changelog statements cover the above schema; by inserting them into the database we facilitate a future upgrade to mt wilson premium because the installer will be able to use these changelog statements to determine what other sql scripts should run during the upgrade

INSERT INTO mw_changelog (ID, APPLIED_AT, DESCRIPTION) VALUES (20120101000000,NOW(),'core - bootstrap');
INSERT INTO mw_changelog (ID, APPLIED_AT, DESCRIPTION) VALUES (20120327214603,NOW(),'core - create changelog');
INSERT INTO mw_changelog (ID, APPLIED_AT, DESCRIPTION) VALUES (20120328172740,NOW(),'core - create 0.5.1 schema');
INSERT INTO mw_changelog (ID, APPLIED_AT, DESCRIPTION) VALUES (20120328173612,NOW(),'core - create 0.5.1 data');
INSERT INTO mw_changelog (ID, APPLIED_AT, DESCRIPTION) VALUES (20120831000000,NOW(),'core - patch rc2');
INSERT INTO mw_changelog (ID, APPLIED_AT, DESCRIPTION) VALUES (20120920085200,NOW(),'core - patch for 1.1');
INSERT INTO mw_changelog (ID, APPLIED_AT, DESCRIPTION) VALUES (20120920085201,NOW(),'core - patch for 1.1 rename tables');
INSERT INTO mw_changelog (ID, APPLIED_AT, DESCRIPTION) VALUES (20121226120200,NOW(),'core - patch for RC3 to remove created_by, updated_by, created_on & updated_on fields');
INSERT INTO mw_changelog (ID, APPLIED_AT, DESCRIPTION) VALUES (20130106235900,NOW(),'core - patch for 1.1 adding tls policy enforcement');
INSERT INTO mw_changelog (ID, APPLIED_AT, DESCRIPTION) VALUES (20130407075500,NOW(),'core - Mt Wilson 1.2 adds AIK_SHA1 field to mw_hosts');

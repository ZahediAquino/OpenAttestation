package com.intel.mtwilson.datatypes;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;
import com.intel.mtwilson.util.net.Hostname;

import org.junit.Assert;
import org.junit.Test;  

import com.intel.mtwilson.validation.Fault;

import static org.junit.Assert.assertEquals;

public class HostnameTest {

@Test
public void testGetHostname(){
	Hostname hostname=new Hostname("hostname");
	assertEquals("hostname",hostname.getHostname());
}

@Test
public void testToString(){
	try {
		String name=InetAddress.getLocalHost().toString();
		Hostname hostname=new Hostname(name);
		assertEquals(name,hostname.toString());
	} catch (UnknownHostException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
	
}
	
@Test
public void testSetHostname(){
	Hostname hostname=new Hostname("hostname");
	hostname.setHostname("hostname");
	assertEquals("hostname",hostname.getHostname());
}

@Test(expected=IllegalArgumentException.class)
public void testSetHostnameNullExceptionIsThrown(){
	Hostname hostname=new Hostname("hostname");
	hostname.setHostname("");		
}

@Test
public void testIsValid(){
	Hostname hostname=new Hostname("hostname");
	hostname.isValid();
}

@Test(expected=IllegalArgumentException.class)	
public void testInvalidHostnameExceptionThrown(){
	Hostname hostname=new Hostname("2,2");	
	hostname.isValid();
}

@Test
public void testEquals(){
	assertEquals(new Hostname("node1"), new Hostname("node1"));
	assertEquals(new Hostname("null"), new Hostname("null"));
	Hostname hostname1=new Hostname("hostname1");
	Hostname hostname2=new Hostname("hostname2");
	Assert.assertFalse("The two obejct is not equal!",hostname1.equals(hostname2));
}

@Test
	public void testGetFaults() {
		Hostname hostname = new Hostname("hostname");
		try {
			hostname = new Hostname("2,2");
		} catch (IllegalArgumentException e) {
			hostname.getFaults();
			assertEquals("Invalid hostname: 2,2", e.getMessage());
		}
	}
}

package com.intel.mtwilson.tls;

import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

import java.security.cert.X509Certificate;
import java.util.List;

import com.intel.mtwilson.util.net.InternetAddress;

public class ArrayCertificateRepositoryTest {
	
	private X509Certificate[] keystore = new X509Certificate[1] ;

	private ArrayCertificateRepository arrayCertificateRepository;
	
	@Before
	public void setUp() throws Exception {
		keystore[0] =CertificateUtils.generateSelfSignedX509Certificate();
		arrayCertificateRepository = new ArrayCertificateRepository(keystore);
	}

	@Test
	public void testGetCertificateForAddress() throws Exception {
		X509Certificate x509 =arrayCertificateRepository.getCertificateForAddress(new InternetAddress("OATServer"));
		assertNotNull(x509);
		assertSame(x509, keystore[0]);
	}

	@Test
	public void testGetCertificateForSubject() throws Exception {
		List<X509Certificate> subjectCerts = arrayCertificateRepository.getCertificateForSubject("CN=OATServer");
		assertNotNull(subjectCerts);
		assertFalse(subjectCerts.isEmpty());
	}

	@Test
	public void testGetCertificateAuthorities() {
		 List<X509Certificate> caCerts = arrayCertificateRepository.getCertificateAuthorities();
		 assertNotNull(caCerts);
		 assertTrue(caCerts.isEmpty());
	}

	@Test
	public void testGetCertificates() {
		List<X509Certificate> allCerts = arrayCertificateRepository.getCertificates();
		assertNotNull(allCerts);
		assertFalse(allCerts.isEmpty());
	}
}

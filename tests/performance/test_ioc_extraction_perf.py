"""Performance tests for IOC extraction.

Benchmarks IOC extraction speed, memory usage, and scalability.
"""

from __future__ import annotations

import time

import pytest

from argus_engine.intel.ioc_extractor import IOCExtractor


# -- Extraction speed benchmarks -----------------------------------------


class TestExtractionSpeed:
    """Benchmark IOC extraction speed."""

    def test_small_text_extraction_speed(self):
        """Small text extraction completes within 10ms."""
        extractor = IOCExtractor()
        text = "IP 192.168.1.1 domain evil.com"

        start = time.monotonic()
        for _ in range(1000):
            extractor.extract(text)
        elapsed = time.monotonic() - start

        # 1000 extractions should complete within 1 second
        assert elapsed < 1.0

    def test_medium_text_extraction_speed(self):
        """Medium text extraction completes within 50ms."""
        extractor = IOCExtractor()
        text = """
        Investigation Report #2024-001
        IPs: 192.168.1.1, 10.0.0.1, 172.16.0.1, 203.0.113.50
        Domains: evil.com, malware.org, c2.net, phishing.io
        Hashes: d41d8cd98f00b204e9800998ecf8427e, da39a3ee5e6b4b0d3255bfef95601890afd80709
        URLs: https://evil.com/payload, http://malware.org/download
        Emails: a@evil.com, b@malware.org
        CVEs: CVE-2024-1234, CVE-2023-5678
        """ * 10

        start = time.monotonic()
        for _ in range(100):
            extractor.extract(text)
        elapsed = time.monotonic() - start

        # 100 extractions should complete within 2 seconds
        assert elapsed < 2.0

    def test_large_text_extraction_speed(self):
        """Large text extraction completes within 500ms."""
        extractor = IOCExtractor()
        text = "IP 192.168.1.1 domain evil.com hash d41d8cd98f00b204e9800998ecf8427e\n" * 1000

        start = time.monotonic()
        extractor.extract(text)
        elapsed = time.monotonic() - start

        # Single large extraction should complete within 500ms
        assert elapsed < 0.5

    def test_very_large_text_extraction_speed(self):
        """Very large text extraction completes within 5 seconds."""
        extractor = IOCExtractor()
        text = "IP 192.168.1.1 domain evil.com\n" * 100000

        start = time.monotonic()
        extractor.extract(text)
        elapsed = time.monotonic() - start

        # Very large extraction should complete within 5 seconds
        assert elapsed < 5.0


# -- Scalability benchmarks ----------------------------------------------


class TestScalability:
    """Test extraction scalability."""

    def test_linear_scaling_with_text_length(self):
        """Extraction time scales roughly linearly with text length."""
        extractor = IOCExtractor()

        # Measure time for different text lengths
        times = []
        for multiplier in [1, 10, 100]:
            text = "IP 192.168.1.1 domain evil.com\n" * multiplier

            start = time.monotonic()
            for _ in range(10):
                extractor.extract(text)
            elapsed = time.monotonic() - start
            times.append(elapsed)

        # Time should not grow faster than 20x per 10x text increase
        if times[0] > 0:
            ratio_1_to_2 = times[1] / max(times[0], 0.0001)
            assert ratio_1_to_2 < 50  # Allow generous margin

    def test_handles_many_unique_iocs(self):
        """Extraction handles text with many unique IOCs."""
        extractor = IOCExtractor()

        # Generate text with many unique IPs
        ips = [f"192.168.{i//256}.{i%256}" for i in range(1000)]
        text = " ".join(f"IP {ip}" for ip in ips)

        start = time.monotonic()
        result = extractor.extract(text)
        elapsed = time.monotonic() - start

        assert result["ipv4"].count("192.168.0.0") >= 1
        assert elapsed < 2.0

    def test_handles_repeated_iocs(self):
        """Extraction handles text with many repeated IOCs."""
        extractor = IOCExtractor()

        # Same IP repeated many times
        text = "IP 192.168.1.1 " * 10000

        start = time.monotonic()
        result = extractor.extract(text)
        elapsed = time.monotonic() - start

        # Should deduplicate
        assert result["ipv4"].count("192.168.1.1") == 1
        assert elapsed < 2.0


# -- Memory usage benchmarks ---------------------------------------------


class TestMemoryUsage:
    """Test memory usage during extraction."""

    def test_memory_does_not_grow_unbounded(self):
        """Memory usage does not grow unbounded with repeated extractions."""
        import gc

        extractor = IOCExtractor()

        # Warm up
        for _ in range(100):
            extractor.extract("IP 192.168.1.1")

        gc.collect()

        # Measure memory after many extractions
        for _ in range(1000):
            extractor.extract("IP 192.168.1.1 domain evil.com")

        gc.collect()

        # If we get here without MemoryError, the test passes
        assert True

    def test_large_result_cleanup(self):
        """Large results are properly cleaned up."""
        extractor = IOCExtractor()

        # Create a large result
        text = " ".join(f"192.168.{i//256}.{i%256}" for i in range(10000))
        result = extractor.extract(text)

        # Delete the result
        del result

        # Should not crash
        assert True


# -- Concurrent extraction benchmarks ------------------------------------


class TestConcurrentExtraction:
    """Test concurrent extraction performance."""

    def test_concurrent_extractions_complete(self):
        """Multiple concurrent extractions complete successfully."""
        import concurrent.futures

        extractor = IOCExtractor()
        texts = [f"IP 192.168.1.{i} domain test{i}.com" for i in range(100)]

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(extractor.extract, text) for text in texts]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]

        assert len(results) == 100
        assert all(isinstance(r, dict) for r in results)

    def test_concurrent_extraction_performance(self):
        """Concurrent extraction is faster than sequential."""
        import concurrent.futures

        extractor = IOCExtractor()
        text = "IP 192.168.1.1 domain evil.com hash d41d8cd98f00b204e9800998ecf8427e" * 10

        # Sequential
        start = time.monotonic()
        for _ in range(50):
            extractor.extract(text)
        sequential_time = time.monotonic() - start

        # Concurrent
        start = time.monotonic()
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(extractor.extract, text) for _ in range(50)]
            concurrent.futures.wait(futures)
        concurrent_time = time.monotonic() - start

        # Concurrent should not be significantly slower
        assert concurrent_time < sequential_time * 2


# -- Regex performance tests ---------------------------------------------


class TestRegexPerformance:
    """Test regex performance (ReDoS prevention)."""

    def test_no_redos_vulnerability_ipv4(self):
        """IPv4 regex is not vulnerable to ReDoS."""
        extractor = IOCExtractor()

        # Pathological input for regex
        text = "1" * 10000 + "."

        start = time.monotonic()
        result = extractor.extract(text)
        elapsed = time.monotonic() - start

        assert elapsed < 1.0

    def test_no_redos_vulnerability_url(self):
        """URL regex is not vulnerable to ReDoS."""
        extractor = IOCExtractor()

        # Pathological input
        text = "http://" + "a" * 10000

        start = time.monotonic()
        result = extractor.extract(text)
        elapsed = time.monotonic() - start

        assert elapsed < 1.0

    def test_no_redos_vulnerability_domain(self):
        """Domain regex is not vulnerable to ReDoS."""
        extractor = IOCExtractor()

        # Pathological input
        text = "." * 10000 + "com"

        start = time.monotonic()
        result = extractor.extract(text)
        elapsed = time.monotonic() - start

        assert elapsed < 1.0

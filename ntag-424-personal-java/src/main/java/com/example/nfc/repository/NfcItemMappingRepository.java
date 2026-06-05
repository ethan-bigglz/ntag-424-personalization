package com.example.nfc.repository;

import com.example.nfc.entity.NfcItemMapping;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface NfcItemMappingRepository extends JpaRepository<NfcItemMapping, String> {
}

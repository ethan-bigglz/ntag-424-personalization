package com.example.nfc.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "nfc_item_mapping")
public class NfcItemMapping {

    @Id
    @Column(name = "uid", length = 14)
    private String uid;

    @Column(name = "item_cd", length = 50, nullable = false)
    private String itemCd;

    @Column(name = "personalized_url", length = 500, nullable = false)
    private String personalizedUrl;

    @Column(name = "created_at", updatable = false)
    private LocalDateTime createdAt = LocalDateTime.now();

    @Column(name = "updated_at")
    private LocalDateTime updatedAt = LocalDateTime.now();

    // Default constructor
    public NfcItemMapping() {}

    public NfcItemMapping(String uid, String itemCd, String personalizedUrl) {
        this.uid = uid;
        this.itemCd = itemCd;
        this.personalizedUrl = personalizedUrl;
    }

    // Getters and Setters
    public String getUid() {
        return uid;
    }

    public void setUid(String uid) {
        this.uid = uid;
    }

    public String getItemCd() {
        return itemCd;
    }

    public void setItemCd(String itemCd) {
        this.itemCd = itemCd;
    }

    public String getPersonalizedUrl() {
        return personalizedUrl;
    }

    public void setPersonalizedUrl(String personalizedUrl) {
        this.personalizedUrl = personalizedUrl;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

    public LocalDateTime getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(LocalDateTime updatedAt) {
        this.updatedAt = updatedAt;
    }
}

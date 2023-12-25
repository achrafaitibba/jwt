package com.achrafaitibba.jwt.configuration.authenticationConfiguration;

public enum LogoutMode {
    ALL_DEVICES("ALL"),
    CURRENT_DEVICE("CURRENT");
    private final String mode;
    LogoutMode(String mode){
        this.mode = mode;
    }
    public String getMode(){
        return this.mode;
    }
}

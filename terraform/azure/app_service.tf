# Azure App Service with intentional TLS misconfiguration.

terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
  }
}

provider "azurerm" {
  features {}
}

resource "azurerm_resource_group" "lab" {
  name     = "rg-guardrails-lab"
  location = "East US"
}

resource "azurerm_app_service_plan" "lab" {
  name                = "asp-guardrails-lab"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name

  sku {
    tier = "Standard"
    size = "S1"
  }
}

resource "azurerm_app_service" "app_service2" {
  name                = "app-guardrails-lab"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
  app_service_plan_id = azurerm_app_service_plan.lab.id

  https_only = true

  site_config {
    # Intentional finding: min_tls_version below 1.2 fails policy.
    min_tls_version = "1.0"
  }

  tags = {
    project = "guardrails-lab"
  }
}

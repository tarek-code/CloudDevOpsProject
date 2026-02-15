terraform {
  cloud {

    organization = "iVolve-project"

    workspaces {
      name = "iVolve-dev"
    }
  }
}

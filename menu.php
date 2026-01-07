<?php
// menu.php - Navbar con layout "Stacked" (Logo/Logout sopra, Menu sotto)

// Assicurati che $_SESSION['role'] e roleLevel() siano disponibili
$currentRole = $_SESSION['role'] ?? 'user'; 
?>

<style>
    /* STILE NAVBAR GENERALE */
    .main-navbar {
        background-color: #ffffff;
        border-bottom: 1px solid #e0e0e0;
        padding-top: 10px;
        padding-bottom: 10px;
        margin-bottom: 20px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.05);
    }

    /* STILE PER IL MENU SU MOBILE (< 992px) */
    @media (max-width: 991.98px) {
        #navbarNavContent {
            background-color: #f8f9fa; /* Sfondo grigio chiaro per contrasto */
            border: 1px solid #dee2e6;
            border-radius: 8px;
            padding: 10px;
            margin-top: 15px; /* Spazio tra la riga logo e il menu */
            box-shadow: 0 4px 8px rgba(0,0,0,0.05);
        }
        
        #navbarNavContent .nav-link {
            padding: 12px 15px;
            border-bottom: 1px solid rgba(0,0,0,0.05);
            color: #333;
            font-weight: 500;
        }
        
        #navbarNavContent .nav-link:last-child {
            border-bottom: none;
        }
        
        #navbarNavContent .nav-link:hover {
            background-color: #e9ecef;
            border-radius: 5px;
        }
    }

    /* STILE SU DESKTOP */
    @media (min-width: 992px) {
        /* Sposta il menu un po' giù rispetto al logo */
        #navbarNavContent {
            margin-top: 10px; 
            border-top: 1px solid #f1f1f1;
            padding-top: 5px;
        }
    }
</style>

<nav class="main-navbar navbar navbar-expand-lg navbar-light">
    <div class="container d-flex flex-wrap">
        
        <div class="d-flex justify-content-between align-items-center w-100">
            
            <a class="navbar-brand p-0 m-0" href="home.php">
                <img src="assets/logocards.png" alt="Vault" style="height: 45px; width: auto;">
            </a>

            <div class="d-flex align-items-center gap-2">
                
                <a class="btn btn-outline-danger d-flex align-items-center gap-2" href="logout.php">
                    <i class="bi bi-box-arrow-right"></i> 
                    <span class="d-none d-md-inline">Logout</span> </a>

                <button class="navbar-toggler border-0 ms-2" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNavContent" aria-controls="navbarNavContent" aria-expanded="false" aria-label="Toggle navigation">
                    <span class="navbar-toggler-icon"></span>
                </button>
            </div>
        </div>

        <div class="collapse navbar-collapse w-100" id="navbarNavContent">
            <div class="navbar-nav gap-1 gap-lg-3 w-100">
                
                <a class="nav-link" href="cards.php"><i class="bi bi-card-list d-lg-none me-2"></i>Lista Schede</a>
                <a class="nav-link" href="card_form.php"><i class="bi bi-plus-circle d-lg-none me-2"></i>Nuova Scheda</a>
                
                <?php if (roleLevel($currentRole) >= roleLevel('admin')): ?>
                    <a class="nav-link" href="manage_users.php"><i class="bi bi-people d-lg-none me-2"></i>Gestione Utenti</a>
                    <a class="nav-link" href="manage_categories.php"><i class="bi bi-tags d-lg-none me-2"></i>Categorie</a>
                <?php endif; ?>

                <?php if (($currentRole === 'admin' || $currentRole === 'superuser')): ?>
                    <a class="nav-link" href="data_transfer.php"><i class="bi bi-arrow-left-right d-lg-none me-2"></i>Import/Export</a>
                <?php endif; ?>

                <a class="nav-link" href="trash.php"><i class="bi bi-trash d-lg-none me-2"></i>Cestino</a>

                <?php if (($currentRole === 'superuser')): ?>
                    <a class="nav-link text-danger fw-bold" href="superuser_panel.php"><i class="bi bi-shield-lock d-lg-none me-2"></i>Pannello Superuser</a>
                <?php endif; ?>
            </div>
        </div>

    </div>
</nav>
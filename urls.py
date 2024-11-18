# Importações necessárias para definir as rotas de URLs
from django.urls import path  # Importa a função path para definir as rotas de URL
from django.contrib.auth import views as auth_views  # Importa as views de autenticação do Django
from . import views  # Importa as views do módulo local

# Lista de padrões de URL para a aplicação 'core'
urlpatterns = [
     path('', views.home, name='home'),  # Página inicial
     path('login/', views.login_usu     , name='login'),  # URL de login]
     path('logout/', auth_views.LogoutView.as_view(), name='logout'),  # URL de logout
     path('cadastro/', views.usuarios, name='listagem_usuarios'),  # URL para cadastro
     path('agendamento/', views.agendamento, name='agendamento'),  # URL para agendamentos
     path('cirurgias/', views.cirurgias, name='cirurgias'),  # URL para cirurgias
     path('exames/', views.exames, name='exames'),  # URL para exames
     path('recepcao/login/', views.recepcao_login, name='recepcao_login'),  # URL para login da recepção
     path('recepcao/dashboard/', views.recepcao_dashboard, name='recepcao_dashboard'),  # URL para dashboard da recepção
     path('alterar-status/<int:agendamento_id>/<str:novo_status>/', views.alterar_status, name='alterar_status'),
     path('login/google/', views.google_login, name='google_login'),
     path('login/google/callback/', views.google_callback, name='google_callback'),
]
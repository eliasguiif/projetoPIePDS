package com.example.controllers;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import com.example.models.Papel;
import com.example.models.Usuario;
import com.example.repositories.PapelRepository;
import com.example.repositories.UsuarioRepository;


@Controller
@RequestMapping("/usuarios")
public class UsuarioController {

	@Autowired
	private PapelRepository pr;
	@Autowired	
	private UsuarioRepository ur;
	
	@GetMapping("/form")
	public String form() {
		return "usuarios/form";
	}
	
	@PostMapping
	public String salvar(Usuario usuario) {
		String senha = usuario.getSenha();
		String senhaCrypto = new BCryptPasswordEncoder().encode(senha);
		usuario.setSenha(senhaCrypto);
		
		Papel papel = pr.findByNome("ROLE_VENDAS");
		List<Papel> papeis = new ArrayList<Papel>();
		papeis.add(papel);
		usuario.setPapeis(papeis);
		
		ur.save(usuario);
		
		return "redirect:/";
	}
	
}

package com.example.controllers;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

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

	@GetMapping
	@PreAuthorize("hasRole('ADMIN')")
	public ModelAndView lista() {
		ModelAndView md = new ModelAndView("usuarios/lista");

		md.addObject("usuarios", ur.findAll());

		return md;
	} 
	@GetMapping("/{id}")
	public ModelAndView selecionarUsuario(@PathVariable Long id) {
		ModelAndView md = new ModelAndView();

		Optional<Usuario> optional = ur.findById(id);
		
		if(optional.isEmpty()) {
			md.setViewName("redirect:/usuarios");
			return md;
		}
		
		md.setViewName("usuarios/edit");
		md.addObject("usuario", optional.get());
		md.addObject("papeis", pr.findAll());
			
		return md;
	}

	@PostMapping("/{id}")
	@PreAuthorize("hasRole('ADMIN')")
	public String salvarPapeis(Usuario usuarioForm) {
		 
		Optional<Usuario> optional = ur.findById(usuarioForm.getId());
		
		if(optional.isEmpty()) {
			
			return "redirect:/usuarios";
			
		}
		Usuario usuario = optional.get();
		usuario.setPapeis(usuarioForm.getPapeis());
		ur.save(usuario);
		return "redirect:/usuarios";
	}
	
}

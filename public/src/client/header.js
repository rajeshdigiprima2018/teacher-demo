'use strict';

define('forum/header', ['forum/header/notifications', 'forum/header/chat'], function (notifications, chat) {
	const module = {};

	module.prepareDOM = function () {
		notifications.prepareDOM();
		chat.prepareDOM();
		handleStatusChange();
		createHeaderTooltips();
		handleLogout();
	};
 


    $(document).ready(function() {
       $("#user_label").css("display", "none");
    });
    $(document).ready(function() {
      $(".breadcrumb").css("display", "none");
    });
     $(document).ready(function() {
      $("#notif_dropdown").css("display", "none");
    });

    $(document).ready(function() {
      $("#chat_dropdown").css("display", "none");
    });
    // $(document).ready(function() {
    //   $(".dropdown-toggle").css("pointer-events", "none");
    // });
    $(document).ready(function() {
      $(".message-header").css("pointer-events", "none");
    });
	function handleStatusChange() {
		$('[component="header/usercontrol"] [data-status]').off('click').on('click', function (e) {
			const status = $(this).attr('data-status');
			socket.emit('user.setStatus', status, function (err) {
				if (err) {
					return app.alertError(err.message);
				}
				$('[data-uid="' + app.user.uid + '"] [component="user/status"], [component="header/profilelink"] [component="user/status"]')
					.removeClass('away online dnd offline')
					.addClass(status);
				$('[component="header/usercontrol"] [data-status]').each(function () {
					$(this).find('span').toggleClass('bold', $(this).attr('data-status') === status);
				});
				app.user.status = status;
			});
			e.preventDefault();
		});
	}

	function createHeaderTooltips() {
		const env = utils.findBootstrapEnvironment();
		if (env === 'xs' || env === 'sm' || utils.isTouchDevice()) {
			return;
		}
		$('#header-menu li a[title]').each(function () {
			$(this).tooltip({
				placement: 'bottom',
				trigger: 'hover',
				title: $(this).attr('title'),
			});
		});


		$('#search-form').tooltip({
			placement: 'bottom',
			trigger: 'hover',
			title: $('#search-button i').attr('title'),
		});


		$('#user_dropdown').tooltip({
			placement: 'bottom',
			trigger: 'hover',
			title: $('#user_dropdown').attr('title'),
		});
	}

	function handleLogout() {
		$('#header-menu .container').on('click', '[component="user/logout"]', function () {
			require(['logout'], function (logout) {
				logout();
			});
			return false;
		});
	}
    	 var url = window.location.href;
	     const userLogout = url.slice(url.indexOf('?')+1);
          if(userLogout == 'logout'){
          	console.log('nagar userLogout',userLogout);
          	require(['logout'], function (logout) {
				logout();
			});
			return false;
          }


	return module;
});

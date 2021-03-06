$(document).ready(function() {
    // Device override ajax calls
    $("[name='override_config']").bootstrapSwitch('offColor','danger');
    $('input[name="override_config"]').on('switchChange.bootstrapSwitch',  function(event, state) {
        event.preventDefault();
        var $this = $(this);
        var attrib = $this.data('attrib');
        var device_id = $this.data('device_id');
        $.ajax({
            type: 'POST',
            url: 'ajax_form.php',
            data: { type: 'override-config', device_id: device_id, attrib: attrib, state: state },
            dataType: 'json',
            success: function(data) {
                if (data.status == 'ok') {
                    toastr.success(data.message);
                }
                else {
                    toastr.error(data.message);
                }
            },
            error: function() {
                toastr.error('Could not set this override');
            }
        });
    });

    // Checkbox config ajax calls
    $("[name='global-config-check']").bootstrapSwitch('offColor','danger');
    $('input[name="global-config-check"]').on('switchChange.bootstrapSwitch',  function(event, state) {
        event.preventDefault();
        var $this = $(this);
        var config_id = $this.data("config_id");
        $.ajax({
            type: 'POST',
            url: 'ajax_form.php',
            data: {type: "update-config-item", config_id: config_id, config_value: state},
            dataType: "json",
            success: function (data) {
                if (data.status == 'ok') {
                    toastr.success('Config updated');
                } else {
                    toastr.error(data.message);
                }
            },
            error: function () {
                toastr.error(data.message);
            }
        });
    });

    // Input field config ajax calls
    $(document).on('blur', 'input[name="global-config-input"]', function(event) {
        event.preventDefault();
        var $this = $(this);
        var config_id = $this.data("config_id");
        var config_value = $this.val();
        $.ajax({
            type: 'POST',
            url: 'ajax_form.php',
            data: {type: "update-config-item", config_id: config_id, config_value: config_value},
            dataType: "json",
            success: function (data) {
                if (data.status == 'ok') {
                    toastr.success('Config updated');
                } else {
                    toastr.error(data.message);
                }
            },
            error: function () {
                toastr.error(data.message);
            }
        });
    });

    // Select config ajax calls
    $( 'select[name="global-config-select"]').change(function(event) {
        event.preventDefault();
        var $this = $(this);
        var config_id = $this.data("config_id");
        var config_value = $this.val();
        $.ajax({
            type: 'POST',
            url: 'ajax_form.php',
            data: {type: "update-config-item", config_id: config_id, config_value: config_value},
            dataType: "json",
            success: function (data) {
                if (data.status == 'ok') {
                    toastr.success('Config updated');
                } else {
                    toastr.error(data.message);
                }
            },
            error: function () {
                toastr.error(data.message);
            }
        });
    });
});

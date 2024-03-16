import SettingsIcon from '@mui/icons-material/SettingsRounded';
import { Box } from '@mui/material';
import AppBar from '@mui/material/AppBar';
import IconButton from '@mui/material/IconButton';
import Link from '@mui/material/Link';
import Toolbar from '@mui/material/Toolbar';
import Typography from '@mui/material/Typography';

const Footer = () => {
    return (
        <AppBar
            elevation={0}
            position="fixed"
            sx = {{
                backgroundColor: theme => theme.palette.background.paper,
                borderTop: '1px solid rgba(0, 0, 0, 0.12)',
                bottom: 0,
                color: theme => theme.palette.text.primary,
                top: 'auto',
            }}
        >
            <Toolbar variant="dense">
                <IconButton>
                    <SettingsIcon />
                </IconButton>
                <Box sx={{ flexGrow: 1 }} />
                <Typography variant="fineprint" sx={{ px: 3 }}>
                    &copy;  {new Date().getFullYear()}&nbsp;
                    <Link
                        color="inherit"
                        href="https://www.credibil.io/"
                        rel="noopener"
                        target="_blank"
                        underline="hover"
                    >
                        Credibil
                    </Link>
                </Typography>
            </Toolbar>
        </AppBar>
    );
};

export default Footer;

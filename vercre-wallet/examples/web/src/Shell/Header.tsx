import { Box } from '@mui/material';
import AppBar from '@mui/material/AppBar';
import Toolbar from '@mui/material/Toolbar';
import Typography from '@mui/material/Typography';

import BrandIcon from './BrandIcon';
import { useShellState } from './Context';

const Header = () => {
    const { shellState } = useShellState();
    return (
        <AppBar
            elevation={0}
            position="fixed"
            sx = {{
                backgroundColor: theme => theme.palette.brandRoyal.main,
            }}
        >
            <Toolbar>
                {shellState.action || <BrandIcon fontSize="large" /> }
                <Typography variant="h4" sx={{ px: 3 }}>{shellState.title}</Typography>
                <Box sx={{ flexGrow: 1 }} />
                {shellState.secondaryAction}
            </Toolbar>
        </AppBar>
    );
};

export default Header;

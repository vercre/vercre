import CheckIcon from '@mui/icons-material/Check';
import DownloadingIcon from '@mui/icons-material/Downloading';
import Box from '@mui/material/Box';
import CircularProgress from '@mui/material/CircularProgress';
import Stack from '@mui/material/Stack';
import Typography from '@mui/material/Typography';

export type RequestStatusProps = {
    status: 'pending' | 'complete',
    title: string,
};

export const RequestStatus = (props: RequestStatusProps) => {

    return (
        <Stack spacing={2} sx={{ pt: 2 }}>
            <Typography sx={{ pb: 2, textAlign: 'center' }}>
                {props.title}
            </Typography>

            <Box sx={{ display: 'flex', alignItems: 'center' }}>
                <Box sx={{ display: 'inline-flex', position: 'relative' }}>
                    <CircularProgress
                        size={68}
                        sx={{
                            color: theme => theme.palette.primary.main,
                            position: 'absolute',
                            top: -20,
                            left: -20,
                            zIndex: 1,
                        }}
                    />
                    {props.status === 'pending'
                        ? <DownloadingIcon color="secondary" />
                        : <CheckIcon color="success" />
                    }
                </Box>
            </Box>
        </Stack>
    );
};

export default RequestStatus;
